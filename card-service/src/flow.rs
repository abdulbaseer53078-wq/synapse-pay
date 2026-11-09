//! One card transaction: decrypt in the HSM, send to the host, and reverse it if the outcome is unknown.
//!
//! The clear PAN exists only inside [`CardFlow::process`]: it's decrypted, sent, and wiped when the call
//! returns. Callers get the outcome plus the BIN and last 4 digits, which PCI DSS allows them to keep.

use std::sync::Arc;
use std::time::Duration;

use host_connector::unified::{outcome, ErrorBody, Outcome, Status};
use host_connector::{Card, Decision, HostConnector, HostError, RequestContext, Transaction, TransactionKind};
use serde::{Deserialize, Serialize};

use crate::hsm::{ClearPan, Hsm, HsmError};
use crate::reversals::ReversalQueue;
use crate::vault::{Vault, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Kind {
    Purchase,
    Authorization,
}

/// What the API backend asks for. Identifiers are the acquirer's (DE 41/42), not registry UUIDs.
#[derive(Debug, Clone, Deserialize)]
pub struct CardRequest {
    pub transaction_id: String,
    pub kind: Kind,
    pub amount: u64,
    pub currency: String,
    pub acquirer_terminal_id: String,
    pub acquirer_merchant_id: String,
    /// The card as the terminal or card form encrypted it. Empty when paying with `card_token`.
    #[serde(default)]
    pub encrypted_card_data: String,
    /// MM/YY, as in the API contract. With `card_token`, the saved card's expiry is used when this is empty.
    #[serde(default)]
    pub card_expiry: String,
    /// Step 29: a saved card (`tok_…`) instead of `encrypted_card_data`. Only valid for the merchant that saved
    /// it, so `merchant_id` (the platform's, not the acquirer's DE 42) is required with it.
    #[serde(default)]
    pub card_token: Option<String>,
    #[serde(default)]
    pub merchant_id: Option<String>,
    #[serde(default)]
    pub pin_block: Option<String>,
    /// Chip payments: the EMV data (BER-TLV) as uppercase hex, sent to the host as DE 55 (spec 1.11.0).
    #[serde(default)]
    pub emv_data: Option<String>,
    /// The acquirers this transaction may use, in preference order (the routing engine's shortlist). Empty means
    /// whatever the connector is configured with, which is what a single-host caller and the tests want.
    #[serde(default)]
    pub host_hint: Vec<String>,
    /// From the X-Trace-Id header (Step 18): the one id that follows the payment from the SDK through Python,
    /// this service and the fleet's events. Not part of the body.
    #[serde(skip)]
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reversal {
    NotNeeded,
    /// The host confirmed the reversal: nothing was charged, the client may retry.
    Reversed,
    /// Couldn't reverse: the transaction stays PENDING until reconciliation settles it.
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct CardResult {
    #[serde(flatten)]
    pub outcome: Outcome,
    pub reversal: Reversal,
    pub card_bin: String,
    pub card_last4: String,
    /// Which host answered, when the caller offered a choice. The audit trail must record this, not the host we
    /// asked for first: those differ whenever the fleet failed over. None when no host answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_used: Option<String>,
}

/// Online (card-not-present) payments in India need the issuer to authenticate the cardholder (RBI's
/// additional factor of authentication), done through EMV 3-D Secure before authorization.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticateRequest {
    pub transaction_id: String,
    pub encrypted_card_data: String,
    #[serde(default)]
    pub encrypted_cvv: Option<String>,
    pub amount: u64,
    pub currency: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ThreeDs {
    /// The issuer authenticated without asking the cardholder anything.
    Frictionless,
    /// The cardholder must complete the issuer's challenge (an OTP in India).
    Challenge,
    /// The issuer refused to authenticate: don't authorize.
    Rejected,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthenticateResult {
    pub three_ds: ThreeDs,
    pub card_bin: String,
    pub card_last4: String,
}

/// Simulated 3-D Secure directory server: the outcome comes from the card number, like sandbox test cards.
/// shortcut: no real 3DS server, directory server or ACS; the challenge page is the sandbox ACS in the backend.
pub fn simulated_three_ds(pan: &str) -> ThreeDs {
    match pan {
        "4242424242424242" => ThreeDs::Frictionless,
        "4000000000003238" => ThreeDs::Rejected,
        // As in India, where nearly every online card payment asks for an OTP.
        _ => ThreeDs::Challenge,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// The card data or PIN block couldn't be used: a client problem, nothing was sent.
    BadCardData(String),
    /// The request itself is unusable (bad expiry, unsupported currency, ...). Nothing was sent.
    BadRequest(String),
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// How long the host gets to answer the transaction.
    pub host: Duration,
    /// Per reversal attempt.
    pub reversal: Duration,
    pub reversal_attempts: u32,
    /// Pause between reversal attempts (the connection that timed out is reconnecting).
    pub reversal_backoff: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            host: Duration::from_millis(1_500),
            reversal: Duration::from_secs(2),
            reversal_attempts: 3,
            reversal_backoff: Duration::from_millis(200),
        }
    }
}

pub struct CardFlow {
    pub hsm: Arc<dyn Hsm>,
    pub host: Arc<dyn HostConnector>,
    pub timeouts: Timeouts,
    /// Saved cards (Step 29); None when no vault is configured, so token payments are refused.
    pub vault: Option<Arc<Vault>>,
    /// Owed reversals that outlive this request (PR 3); None without a database, so they are only logged.
    pub reversals: Option<Arc<ReversalQueue>>,
}

/// MM/YY → YYMM (DE 14).
pub fn expiry_yymm(mm_yy: &str) -> Result<String, FlowError> {
    let bad = || FlowError::BadRequest("card_expiry must be MM/YY".into());
    let (mm, yy) = mm_yy.split_once('/').ok_or_else(bad)?;
    let month: u8 = mm.parse().map_err(|_| bad())?;
    if mm.len() != 2 || yy.len() != 2 || !(1..=12).contains(&month) || !yy.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    Ok(format!("{yy}{mm}"))
}

/// DE 55 holds at most 255 bytes; anything that isn't even-length uppercase hex is refused, not repaired.
fn icc_bytes(hex: &str) -> Result<Vec<u8>, FlowError> {
    let bad = || FlowError::BadCardData("emv_data must be uppercase hex, at most 255 bytes".into());
    if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > 510 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)) {
        return Err(bad());
    }
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| bad())).collect()
}

fn card_error(e: HsmError) -> FlowError {
    FlowError::BadCardData(e.to_string())
}

impl CardFlow {
    pub fn authenticate(&self, req: &AuthenticateRequest) -> Result<AuthenticateResult, FlowError> {
        let pan = self.hsm.decrypt_pan(&req.encrypted_card_data).map_err(card_error)?;
        if let Some(cvv) = &req.encrypted_cvv {
            self.hsm.verify_cvv(cvv).map_err(card_error)?;
        }
        Ok(AuthenticateResult { three_ds: simulated_three_ds(pan.as_str()), card_bin: pan.bin(), card_last4: pan.last4() })
    }

    /// The card to authorize with: decrypted from the request's envelope, or a saved card from the vault.
    async fn card(&self, req: &CardRequest) -> Result<(ClearPan, String), FlowError> {
        match (&req.card_token, req.encrypted_card_data.is_empty()) {
            (None, false) => Ok((self.hsm.decrypt_pan(&req.encrypted_card_data).map_err(card_error)?,
                                 req.card_expiry.clone())),
            (Some(token), true) => {
                let vault = self.vault.as_ref().ok_or_else(|| FlowError::BadRequest("no token vault here".into()))?;
                let merchant = req.merchant_id.as_deref()
                    .ok_or_else(|| FlowError::BadRequest("merchant_id is required with card_token".into()))?;
                let (pan, saved_expiry) = vault.resolve(merchant, token).await.map_err(|e| match e {
                    VaultError::UnknownToken => FlowError::BadCardData("unknown or revoked card_token".into()),
                    VaultError::BadCardData(why) => FlowError::BadCardData(why),
                    VaultError::BadRequest(why) | VaultError::Unavailable(why) => FlowError::BadRequest(why),
                })?;
                let expiry = if req.card_expiry.is_empty() { saved_expiry } else { req.card_expiry.clone() };
                Ok((pan, expiry))
            }
            _ => Err(FlowError::BadRequest("give exactly one of encrypted_card_data or card_token".into())),
        }
    }

    pub async fn process(&self, req: &CardRequest) -> Result<CardResult, FlowError> {
        let (pan, card_expiry) = self.card(req).await?;
        let expiry = expiry_yymm(&card_expiry)?;
        if let Some(pin) = &req.pin_block {
            self.hsm.verify_pin_block(pin, &pan).map_err(card_error)?;
        }
        let (card_bin, card_last4) = (pan.bin(), pan.last4());
        let icc = req.emv_data.as_deref().map(icc_bytes).transpose()?;
        let txn = Transaction {
            transaction_id: req.transaction_id.clone(),
            kind: match req.kind {
                Kind::Purchase => TransactionKind::Purchase,
                Kind::Authorization => TransactionKind::Authorization,
            },
            amount_minor: req.amount,
            currency: req.currency.clone(),
            merchant_id: req.acquirer_merchant_id.clone(),
            terminal_id: req.acquirer_terminal_id.clone(),
            card: Card { pan: pan.as_str().to_owned(), expiry, icc },
        };
        // Without a trace id from the caller, the transaction id still ties this request's events together.
        let trace = req.trace_id.clone().unwrap_or_else(|| req.transaction_id.clone());
        let mut ctx = RequestContext::with_timeout(self.timeouts.host, &trace);
        ctx.host_hint = req.host_hint.clone();
        let result = self.host.send_transaction(&ctx, &txn).await;
        // Capture the winner before `outcome` borrows the result: on failure no host answered, so there is none.
        let host_used = match &result {
            Ok(response) if !response.host_used.is_empty() => Some(response.host_used.clone()),
            _ => None,
        };
        let mut outcome = outcome(&txn.kind, &result);
        let mut reversal = Reversal::NotNeeded;
        if outcome.status == Status::Pending {
            reversal = self.reverse(&txn, &trace).await;
            if reversal == Reversal::Failed {
                // Still owed: queue it before the card number is wiped below, or nothing will ever send it.
                match &self.reversals {
                    Some(queue) => if let Err(e) = queue.enqueue(&txn).await {
                        eprintln!("REVERSAL NOT QUEUED for {}: {e}", txn.transaction_id);
                    },
                    None => eprintln!("REVERSAL OWED for {}: no reversal queue configured", txn.transaction_id),
                }
            }
            if reversal == Reversal::Reversed {
                outcome = Outcome {
                    status: Status::Failed,
                    method_reference: None,
                    auth_code: None,
                    error: Some(ErrorBody {
                        error_code: "HOST_TIMEOUT",
                        error_message: "the acquirer didn't answer in time; the attempt was reversed, so the \
                                        customer was not charged"
                            .into(),
                        error_category: "SYSTEM_ERROR",
                        retryable: true,
                    }),
                };
            }
        }
        // `txn.card` holds a copy of the PAN: wipe it before returning.
        let mut txn = txn;
        zeroize::Zeroize::zeroize(&mut txn.card.pan);
        Ok(CardResult { outcome, reversal, card_bin, card_last4, host_used })
    }

    /// Sends the reversal until the host confirms it or attempts run out. A decline of a reversal (e.g.
    /// "original not found") also counts as failed: someone has to look at it.
    async fn reverse(&self, original: &Transaction, trace: &str) -> Reversal {
        let mut reversal = Transaction {
            transaction_id: format!("{}-rev", original.transaction_id),
            kind: TransactionKind::Reversal { original_transaction_id: original.transaction_id.clone() },
            ..original.clone()
        };
        let mut result = Reversal::Failed;
        for attempt in 0..self.timeouts.reversal_attempts {
            if attempt > 0 {
                tokio::time::sleep(self.timeouts.reversal_backoff).await;
            }
            let mut ctx = RequestContext::with_timeout(self.timeouts.reversal, trace); // same trace as the purchase
            // Deliberately empty. The purchase timed out, so the fleet never reported which host answered; the
            // only reversal that means anything is on the host holding the original, and the fleet must try the
            // hosts rather than have this layer pick one it cannot know.
            ctx.host_hint = vec![];
            match self.host.send_transaction(&ctx, &reversal).await {
                Ok(resp) => {
                    if matches!(resp.decision, Decision::Approved { .. }) {
                        result = Reversal::Reversed;
                    }
                    break;
                }
                // Not delivered, or no answer: the reversal itself is safe to repeat.
                Err(HostError::Unavailable(_) | HostError::Timeout | HostError::ConnectionLost(_)
                    | HostError::Protocol(_)) => {}
            }
        }
        zeroize::Zeroize::zeroize(&mut reversal.card.pan);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_conversion() {
        assert_eq!(expiry_yymm("08/28").unwrap(), "2808");
        for bad in ["8/28", "13/28", "00/28", "08-28", "08/2a", "08/2028"] {
            assert!(expiry_yymm(bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod icc_tests {
    use super::icc_bytes;

    #[test]
    fn emv_data_is_strict_uppercase_hex_up_to_255_bytes() {
        assert_eq!(icc_bytes("9F2608AB").unwrap(), vec![0x9F, 0x26, 0x08, 0xAB]);
        for bad in ["", "9F2", "9f26", "9F26ZZ", &"AB".repeat(256)] {
            assert!(icc_bytes(bad).is_err(), "{bad:?}");
        }
    }
}
