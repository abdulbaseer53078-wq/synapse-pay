//! One card transaction: decrypt in the HSM, send to the host, and reverse it if the outcome is unknown.
//!
//! The clear PAN exists only inside [`CardFlow::process`]: it's decrypted, sent, and wiped when the call
//! returns. Callers get the outcome plus the BIN and last 4 digits, which PCI DSS allows them to keep.

use std::sync::Arc;
use std::time::Duration;

use host_connector::unified::{outcome, ErrorBody, Outcome, Status};
use host_connector::{Card, Decision, HostConnector, HostError, RequestContext, Transaction, TransactionKind};
use serde::{Deserialize, Serialize};

use crate::hsm::{Hsm, HsmError};

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
    pub encrypted_card_data: String,
    /// MM/YY, as in the API contract.
    pub card_expiry: String,
    #[serde(default)]
    pub pin_block: Option<String>,
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
}

/// Online (card-not-present) payments in India need the issuer to authenticate the cardholder (RBI's
/// additional factor of authentication), done through EMV 3-D Secure before authorization.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticateRequest {
    pub transaction_id: String,
    pub encrypted_card_data: String,
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
}

/// MM/YY → YYMM (DE 14).
fn expiry_yymm(mm_yy: &str) -> Result<String, FlowError> {
    let bad = || FlowError::BadRequest("card_expiry must be MM/YY".into());
    let (mm, yy) = mm_yy.split_once('/').ok_or_else(bad)?;
    let month: u8 = mm.parse().map_err(|_| bad())?;
    if mm.len() != 2 || yy.len() != 2 || !(1..=12).contains(&month) || !yy.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    Ok(format!("{yy}{mm}"))
}

fn card_error(e: HsmError) -> FlowError {
    FlowError::BadCardData(e.to_string())
}

impl CardFlow {
    pub fn authenticate(&self, req: &AuthenticateRequest) -> Result<AuthenticateResult, FlowError> {
        let pan = self.hsm.decrypt_pan(&req.encrypted_card_data).map_err(card_error)?;
        Ok(AuthenticateResult { three_ds: simulated_three_ds(pan.as_str()), card_bin: pan.bin(), card_last4: pan.last4() })
    }

    pub async fn process(&self, req: &CardRequest) -> Result<CardResult, FlowError> {
        let expiry = expiry_yymm(&req.card_expiry)?;
        let pan = self.hsm.decrypt_pan(&req.encrypted_card_data).map_err(card_error)?;
        if let Some(pin) = &req.pin_block {
            self.hsm.verify_pin_block(pin, &pan).map_err(card_error)?;
        }
        let (card_bin, card_last4) = (pan.bin(), pan.last4());
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
            card: Card { pan: pan.as_str().to_owned(), expiry },
        };
        let ctx = RequestContext::with_timeout(self.timeouts.host, &req.transaction_id);
        let result = self.host.send_transaction(&ctx, &txn).await;
        let mut outcome = outcome(&txn.kind, &result);
        let mut reversal = Reversal::NotNeeded;
        if outcome.status == Status::Pending {
            reversal = self.reverse(&txn).await;
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
        Ok(CardResult { outcome, reversal, card_bin, card_last4 })
    }

    /// Sends the reversal until the host confirms it or attempts run out. A decline of a reversal (e.g.
    /// "original not found") also counts as failed: someone has to look at it.
    async fn reverse(&self, original: &Transaction) -> Reversal {
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
            let ctx = RequestContext::with_timeout(self.timeouts.reversal, &reversal.transaction_id);
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
