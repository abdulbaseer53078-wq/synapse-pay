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
//!
//! Browsers and merchant apps (Step 6) have no injected keys, so they encrypt to the HSM's public
//! *checkout key* instead (ECIES over P-256, which WebCrypto, Android and iOS all support natively):
//!
//! ```text
//! sp2.<ephemeral P-256 public key, 65-byte uncompressed SEC1, base64url>.<12-byte nonce || AES-GCM ct+tag>
//! key = HKDF-SHA256(ECDH shared secret, salt = ephemeral public key bytes,
//!                   info = "synapsepay/checkout/v1/<usage>")
//! ```
//!
//! shortcut: the checkout private key is loaded from a PEM file (or generated at startup); in production it
//! lives in the HSM and never leaves it.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "sp1";
const CHECKOUT_PREFIX: &str = "sp2";
/// Vault ciphertexts, key version 1 (Step 29).
const VAULT_PREFIX: &str = "sv1";
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
    /// A PAN or network token from somewhere other than an envelope (the vault, a token service): checked the same.
    pub fn from_digits(pan: &str) -> Result<Self, HsmError> {
        if !(13..=19).contains(&pan.len()) || !pan.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HsmError::InvalidContent("PAN must be 13 to 19 digits"));
        }
        if !luhn_ok(pan) {
            return Err(HsmError::InvalidContent("PAN fails the Luhn check"));
        }
        Ok(ClearPan(Zeroizing::new(pan.to_owned())))
    }

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

    /// Checks an encrypted card security code (CVV2/CVC2) is 3 or 4 digits.
    /// shortcut: checked, not forwarded; the synthetic host dialect has no field for it yet.
    fn verify_cvv(&self, _envelope: &str) -> Result<(), HsmError> {
        Err(HsmError::Malformed("CVV checks are not supported"))
    }

    /// The public checkout key as a JWK, for browsers and apps to encrypt card data to (sp2), if configured.
    fn checkout_public_jwk(&self) -> Option<String> {
        None
    }

    /// Step 29: encrypts a PAN (or network token) for the vault, bound to its token so a ciphertext can't be
    /// moved to another row. The key never leaves the HSM.
    fn vault_seal(&self, _token: &str, _pan: &ClearPan) -> Result<String, HsmError> {
        Err(HsmError::Malformed("this HSM has no vault key"))
    }

    fn vault_open(&self, _token: &str, _sealed: &str) -> Result<ClearPan, HsmError> {
        Err(HsmError::Malformed("this HSM has no vault key"))
    }

    /// A keyed fingerprint of the card for one merchant (hex HMAC-SHA256). Keyed, because a PAN has so few
    /// unknown digits that a plain hash is reversed by trying them all; PCI DSS 3.5.1 requires a keyed hash.
    fn pan_fingerprint(&self, _merchant_id: &str, _pan: &ClearPan) -> Result<String, HsmError> {
        Err(HsmError::Malformed("this HSM has no vault key"))
    }
}

pub struct SimHsm {
    bdk: Zeroizing<Vec<u8>>,
    checkout: Option<p256::SecretKey>,
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
        Ok(Self { bdk: Zeroizing::new(bdk), checkout: None })
    }

    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let hex = hex.trim();
        if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("BDK must be hex".into());
        }
        let bytes = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        Self::new(bytes)
    }

    /// The vault's keys (Step 29).
    /// shortcut: derived from the BDK with their own HKDF labels; a real HSM generates the vault KEK and the
    /// fingerprint key on its own and never exports either. Rotation: a new label and prefix (sv2) per key version.
    fn vault_key(&self, purpose: &str) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, &self.bdk)
            .expand(format!("synapsepay/vault/v1/{purpose}").as_bytes(), key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        key
    }

    /// Enables sp2 (browser and app) envelopes with this private checkout key.
    pub fn with_checkout_key(mut self, key: p256::SecretKey) -> Self {
        self.checkout = Some(key);
        self
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
        let (Some(prefix), Some(ksn), Some(body), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(HsmError::Malformed("expected sp1.<ksn>.<ciphertext> or sp2.<key>.<ciphertext>"));
        };
        match prefix {
            PREFIX => {}
            CHECKOUT_PREFIX => return self.open_checkout(ksn, body, usage),
            _ => return Err(HsmError::Malformed("unknown envelope version")),
        }
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

    fn checkout_key(epk: &[u8], shared: &p256::ecdh::SharedSecret, usage: &str) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0u8; 32]);
        shared
            .extract::<Sha256>(Some(epk))
            .expand(format!("synapsepay/checkout/v1/{usage}").as_bytes(), key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        key
    }

    fn open_checkout(&self, epk: &str, body: &str, usage: &str) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        let secret = self.checkout.as_ref().ok_or(HsmError::Malformed("checkout encryption is not enabled"))?;
        let epk = B64.decode(epk).map_err(|_| HsmError::Malformed("ephemeral key is not base64url"))?;
        let body = B64.decode(body).map_err(|_| HsmError::Malformed("ciphertext is not base64url"))?;
        let public = p256::PublicKey::from_sec1_bytes(&epk)
            .map_err(|_| HsmError::Malformed("ephemeral key is not a P-256 point"))?;
        if epk.len() != 65 || body.len() <= NONCE_LEN + 16 {
            return Err(HsmError::Malformed("wrong key or ciphertext length"));
        }
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
        let key = Self::checkout_key(&epk, &shared, usage);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
        let (nonce, ciphertext) = body.split_at(NONCE_LEN);
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: usage.as_bytes() })
            .map(Zeroizing::new)
            .map_err(|_| HsmError::Undecryptable)
    }

    /// What a browser or app does: encrypt to the checkout public key. For tests and simulators.
    pub fn seal_checkout(public: &p256::PublicKey, ephemeral: &p256::SecretKey, nonce: [u8; NONCE_LEN], usage: &str,
                         plaintext: &[u8]) -> String {
        let epk = ephemeral.public_key().to_sec1_bytes();
        let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), public.as_affine());
        let key = Self::checkout_key(&epk, &shared, usage);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: usage.as_bytes() })
            .expect("AES-GCM encryption can't fail for these sizes");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        format!("{CHECKOUT_PREFIX}.{}.{}", B64.encode(&epk), B64.encode(out))
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
    sum.is_multiple_of(10)
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
        ClearPan::from_digits(pan)
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

    fn verify_cvv(&self, envelope: &str) -> Result<(), HsmError> {
        let cvv = self.open(envelope, "cvv")?;
        if !(3..=4).contains(&cvv.len()) || !cvv.iter().all(u8::is_ascii_digit) {
            return Err(HsmError::InvalidContent("security code must be 3 or 4 digits"));
        }
        Ok(())
    }

    fn checkout_public_jwk(&self) -> Option<String> {
        self.checkout.as_ref().map(|k| k.public_key().to_jwk_string())
    }

    fn vault_seal(&self, token: &str, pan: &ClearPan) -> Result<String, HsmError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let key = self.vault_key("kek");
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: pan.as_str().as_bytes(), aad: token.as_bytes() })
            .map_err(|_| HsmError::Malformed("vault encryption failed"))?;
        let mut body = nonce.to_vec();
        body.extend_from_slice(&ciphertext);
        Ok(format!("{VAULT_PREFIX}.{}", B64.encode(body)))
    }

    fn vault_open(&self, token: &str, sealed: &str) -> Result<ClearPan, HsmError> {
        let body = sealed.strip_prefix(VAULT_PREFIX).and_then(|rest| rest.strip_prefix('.'))
            .ok_or(HsmError::Malformed("not a vault ciphertext of a known key version"))?;
        let body = B64.decode(body).map_err(|_| HsmError::Malformed("ciphertext is not base64url"))?;
        if body.len() <= NONCE_LEN + 16 {
            return Err(HsmError::Malformed("ciphertext too short"));
        }
        let key = self.vault_key("kek");
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
        let (nonce, ciphertext) = body.split_at(NONCE_LEN);
        let clear = Zeroizing::new(
            cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: token.as_bytes() })
                .map_err(|_| HsmError::Undecryptable)?,
        );
        let pan = std::str::from_utf8(&clear).map_err(|_| HsmError::InvalidContent("PAN is not text"))?;
        ClearPan::from_digits(pan)
    }

    fn pan_fingerprint(&self, merchant_id: &str, pan: &ClearPan) -> Result<String, HsmError> {
        use hmac::Mac;
        let key = self.vault_key("fingerprint");
        let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key.as_ref()).expect("any key length");
        mac.update(merchant_id.as_bytes());
        mac.update(b"|");
        mac.update(pan.as_str().as_bytes());
        Ok(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
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
    fn checkout_envelope_round_trip() {
        let server = p256::SecretKey::random(&mut rand_core::OsRng);
        let hsm = hsm().with_checkout_key(server.clone());
        let browser = p256::SecretKey::random(&mut rand_core::OsRng);
        let envelope = SimHsm::seal_checkout(&server.public_key(), &browser, [7; 12], "data", PAN.as_bytes());
        assert!(envelope.starts_with("sp2."));
        assert_eq!(hsm.decrypt_pan(&envelope).unwrap().as_str(), PAN);
        assert!(hsm.checkout_public_jwk().unwrap().contains("\"crv\":\"P-256\""));
        // Encrypted to someone else's key: undecryptable.
        let other = p256::SecretKey::random(&mut rand_core::OsRng);
        let wrong = SimHsm::seal_checkout(&other.public_key(), &browser, [7; 12], "data", PAN.as_bytes());
        assert_eq!(hsm.decrypt_pan(&wrong).unwrap_err(), HsmError::Undecryptable);
        // Without a checkout key configured, sp2 is refused.
        assert!(matches!(self::hsm().decrypt_pan(&envelope), Err(HsmError::Malformed(_))));
    }

    #[test]
    fn bad_bdk_rejected() {
        assert!(SimHsm::new(vec![0; 10]).is_err());
        assert!(SimHsm::from_hex("zz").is_err());
    }
}
