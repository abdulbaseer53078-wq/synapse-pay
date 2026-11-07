//! Simulated HSM (Stage 1, Step 5): decrypts the card data and PIN blocks terminals send.
//!
//! The real thing is a payment HSM holding the base derivation key (BDK) for ANSI X9.24-3 AES DUKPT: the
//! terminal's secure element derives a fresh key per transaction from its initial key and a key serial
//! number (KSN), and only the HSM can derive the same key from the BDK. This simulator keeps that shape
//! (one secret base key, a per-transaction key derived from the KSN, nothing reusable on the wire) with
//! simpler maths, so terminals, tests and this service can all speak it today.
//!
//! shortcut: SIM-DUKPT is HKDF-SHA256(BDK, salt = KSN) + AES-256-GCM, not X9.24-3, and the BDK comes from
//! an environment variable. Replace with a real HSM (and X9.24-3 on the terminals) before any live card.
//! The [`Hsm`] trait is the seam: callers never see which one they have.
//!
//! Envelope, as the terminal sends it in `encrypted_card_data` (and `pin_block`):
//!
//! ```text
//! sp1.<KSN, 10 bytes, base64url>.<12-byte nonce || AES-GCM ciphertext+tag, base64url>
//! ```
//!
//! The AAD is the usage ("data" or "pin"), so a PIN block can't be replayed as card data or vice versa.
//! Card data plaintext is the PAN as ASCII digits. A PIN block's plaintext is an ISO 9564 format 0 block.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "sp1";
const KSN_LEN: usize = 10;
const NONCE_LEN: usize = 12;

/// Why the HSM refused. Messages never contain key or card material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HsmError {
    /// Not an `sp1.` envelope, bad base64, wrong lengths.
    Malformed(&'static str),
    /// Authentication failed: wrong key, tampered or swapped ciphertext.
    Undecryptable,
    /// Decrypted, but not a plausible PAN / PIN block.
    InvalidContent(&'static str),
}

impl std::fmt::Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed encrypted data: {why}"),
            Self::Undecryptable => write!(f, "encrypted data could not be decrypted"),
            Self::InvalidContent(why) => write!(f, "decrypted data is invalid: {why}"),
        }
    }
}

/// A clear PAN. Wiped from memory when dropped; `Debug` shows the last 4 digits only.
pub struct ClearPan(Zeroizing<String>);

impl ClearPan {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn last4(&self) -> String {
        self.0[self.0.len() - 4..].to_owned()
    }

    /// First 6 digits: identifies the issuer, allowed on receipts and in reporting under PCI DSS.
    pub fn bin(&self) -> String {
        self.0[..6].to_owned()
    }
}

impl std::fmt::Debug for ClearPan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClearPan(****{})", self.last4())
    }
}

/// The operations the transaction flow needs from an HSM.
pub trait Hsm: Send + Sync {
    fn decrypt_pan(&self, envelope: &str) -> Result<ClearPan, HsmError>;

    /// Checks a PIN block decrypts and is well-formed for this PAN.
    /// shortcut: a real HSM translates it to the acquirer's zone PIN key for DE 52; the synthetic host
    /// dialect has no DE 52 yet, so the block is checked here and not forwarded.
    fn verify_pin_block(&self, envelope: &str, pan: &ClearPan) -> Result<(), HsmError>;
}

pub struct SimHsm {
    bdk: Zeroizing<Vec<u8>>,
}

impl SimHsm {
    /// `bdk` must be 16 or 32 bytes.
    pub fn new(bdk: Vec<u8>) -> Result<Self, String> {
        if bdk.len() != 16 && bdk.len() != 32 {
            let len = bdk.len();
            let mut bdk = bdk;
            bdk.zeroize();
            return Err(format!("BDK must be 16 or 32 bytes, got {len}"));
        }
        Ok(Self { bdk: Zeroizing::new(bdk) })
    }

    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let hex = hex.trim();
        if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("BDK must be hex".into());
        }
        let bytes = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        Self::new(bytes)
    }

    fn key(&self, ksn: &[u8], usage: &str) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(ksn), &self.bdk)
            .expand(format!("synapsepay/sim-dukpt/v1/{usage}").as_bytes(), key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        key
    }

    fn open(&self, envelope: &str, usage: &str) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        let mut parts = envelope.split('.');
        let (Some(PREFIX), Some(ksn), Some(body), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(HsmError::Malformed("expected sp1.<ksn>.<ciphertext>"));
        };
        let ksn = B64.decode(ksn).map_err(|_| HsmError::Malformed("KSN is not base64url"))?;
        let body = B64.decode(body).map_err(|_| HsmError::Malformed("ciphertext is not base64url"))?;
        if ksn.len() != KSN_LEN {
            return Err(HsmError::Malformed("KSN must be 10 bytes"));
        }
        if body.len() <= NONCE_LEN + 16 {
            return Err(HsmError::Malformed("ciphertext too short"));
        }
        let key = self.key(&ksn, usage);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
        let (nonce, ciphertext) = body.split_at(NONCE_LEN);
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: usage.as_bytes() })
            .map(Zeroizing::new)
            .map_err(|_| HsmError::Undecryptable)
    }

    /// What a simulated terminal does: encrypt under the key for this KSN. Used by tests and the demo.
    pub fn seal(&self, ksn: [u8; KSN_LEN], nonce: [u8; NONCE_LEN], usage: &str, plaintext: &[u8]) -> String {
        let key = self.key(&ksn, usage);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: usage.as_bytes() })
            .expect("AES-GCM encryption can't fail for these sizes");
        let mut body = nonce.to_vec();
        body.extend_from_slice(&ciphertext);
        format!("{PREFIX}.{}.{}", B64.encode(ksn), B64.encode(body))
    }
}

/// Luhn check digit validation.
fn luhn_ok(pan: &str) -> bool {
    let sum: u32 = pan
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 1 { if d * 2 > 9 { d * 2 - 9 } else { d * 2 } } else { d }
        })
        .sum();
    sum % 10 == 0
}

/// The 8-byte PAN field of an ISO 9564 format 0 block: 0000 + the 12 PAN digits before the check digit.
fn pan_field(pan: &str) -> [u8; 8] {
    let digits = &pan[pan.len() - 13..pan.len() - 1];
    let mut field = [0u8; 8];
    for (i, pair) in digits.as_bytes().chunks(2).enumerate() {
        field[2 + i] = ((pair[0] - b'0') << 4) | (pair[1] - b'0');
    }
    field
}

impl Hsm for SimHsm {
    fn decrypt_pan(&self, envelope: &str) -> Result<ClearPan, HsmError> {
        let clear = self.open(envelope, "data")?;
        let pan = std::str::from_utf8(&clear).map_err(|_| HsmError::InvalidContent("PAN is not text"))?;
        if !(13..=19).contains(&pan.len()) || !pan.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HsmError::InvalidContent("PAN must be 13 to 19 digits"));
        }
        if !luhn_ok(pan) {
            return Err(HsmError::InvalidContent("PAN fails the Luhn check"));
        }
        Ok(ClearPan(Zeroizing::new(pan.to_owned())))
    }

    fn verify_pin_block(&self, envelope: &str, pan: &ClearPan) -> Result<(), HsmError> {
        let block = self.open(envelope, "pin")?;
        if block.len() != 8 {
            return Err(HsmError::InvalidContent("PIN block must be 8 bytes"));
        }
        let field = pan_field(pan.as_str());
        let pin: Zeroizing<Vec<u8>> = Zeroizing::new(block.iter().zip(field).map(|(a, b)| a ^ b).collect());
        let (format, length) = (pin[0] >> 4, usize::from(pin[0] & 0x0f));
        if format != 0 || !(4..=12).contains(&length) {
            return Err(HsmError::InvalidContent("not an ISO 9564 format 0 PIN block for this card"));
        }
        let nibbles: Zeroizing<Vec<u8>> = Zeroizing::new(pin[1..].iter().flat_map(|b| [b >> 4, b & 0x0f]).collect());
        let digits_ok = nibbles[..length].iter().all(|&n| n <= 9);
        let padding_ok = nibbles[length..].iter().all(|&n| n == 0x0f);
        if !(digits_ok && padding_ok) {
            return Err(HsmError::InvalidContent("not an ISO 9564 format 0 PIN block for this card"));
        }
        Ok(())
    }
}

/// Builds an ISO 9564 format 0 clear PIN block (what a PIN pad encrypts). For simulated terminals and tests.
pub fn format0_pin_block(pin: &str, pan: &str) -> [u8; 8] {
    assert!((4..=12).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit()));
    let mut nibbles = vec![0u8, pin.len() as u8];
    nibbles.extend(pin.bytes().map(|b| b - b'0'));
    nibbles.resize(16, 0x0f);
    let field = pan_field(pan);
    let mut block = [0u8; 8];
    for i in 0..8 {
        block[i] = ((nibbles[2 * i] << 4) | nibbles[2 * i + 1]) ^ field[i];
    }
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAN: &str = "4111111111111111";

    fn hsm() -> SimHsm {
        SimHsm::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap()
    }

    fn card(hsm: &SimHsm, pan: &str) -> String {
        hsm.seal([1; 10], [2; 12], "data", pan.as_bytes())
    }

    #[test]
    fn round_trip() {
        let hsm = hsm();
        let pan = hsm.decrypt_pan(&card(&hsm, PAN)).unwrap();
        assert_eq!(pan.as_str(), PAN);
        assert_eq!(format!("{pan:?}"), "ClearPan(****1111)");
        assert_eq!((pan.bin(), pan.last4()), ("411111".into(), "1111".into()));
    }

    #[test]
    fn wrong_key_is_undecryptable() {
        let other = SimHsm::new(vec![9; 32]).unwrap();
        assert_eq!(hsm().decrypt_pan(&card(&other, PAN)).unwrap_err(), HsmError::Undecryptable);
    }

    #[test]
    fn tampered_ciphertext_is_undecryptable() {
        let hsm = hsm();
        let mut envelope = card(&hsm, PAN);
        let last = envelope.pop().unwrap();
        envelope.push(if last == 'A' { 'B' } else { 'A' });
        assert!(hsm.decrypt_pan(&envelope).is_err());
    }

    #[test]
    fn pin_block_cannot_pass_as_card_data() {
        let hsm = hsm();
        let pin = hsm.seal([1; 10], [2; 12], "pin", PAN.as_bytes());
        assert_eq!(hsm.decrypt_pan(&pin).unwrap_err(), HsmError::Undecryptable);
    }

    #[test]
    fn malformed_envelopes() {
        let hsm = hsm();
        for bad in ["", "sp1", "sp2.AAAA.BBBB", "sp1.***.AAAA", "sp1.AAAA.AAAA", "sp1.AQEBAQEBAQEBAQ.AA.x"] {
            assert!(matches!(hsm.decrypt_pan(bad), Err(HsmError::Malformed(_))), "{bad}");
        }
    }

    #[test]
    fn invalid_pan_rejected() {
        let hsm = hsm();
        assert!(matches!(hsm.decrypt_pan(&card(&hsm, "4111111111111112")), Err(HsmError::InvalidContent(_))));
        assert!(matches!(hsm.decrypt_pan(&card(&hsm, "41111")), Err(HsmError::InvalidContent(_))));
    }

    #[test]
    fn pin_block_checks() {
        let hsm = hsm();
        let pan = hsm.decrypt_pan(&card(&hsm, PAN)).unwrap();
        let good = hsm.seal([3; 10], [4; 12], "pin", &format0_pin_block("1234", PAN));
        hsm.verify_pin_block(&good, &pan).unwrap();
        // A block made for another card doesn't decode as format 0 for this one.
        let other = hsm.seal([3; 10], [4; 12], "pin", &format0_pin_block("1234", "5500000000000004"));
        assert!(hsm.verify_pin_block(&other, &pan).is_err());
    }

    #[test]
    fn bad_bdk_rejected() {
        assert!(SimHsm::new(vec![0; 10]).is_err());
        assert!(SimHsm::from_hex("zz").is_err());
    }
}
