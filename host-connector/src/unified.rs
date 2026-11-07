//! The Unified Transaction Model (spec/openapi.yaml) on both sides of a host connector:
//! a `TransactionRequest` in, a status plus the spec's `error` object out.

use serde::{Deserialize, Serialize};

use crate::{Card, Decision, DeclineCategory, HostError, HostResponse, Transaction, TransactionKind};

/// The fields of the spec's `TransactionRequest` a host connector needs. Other fields are ignored here;
/// the API validates them against the spec.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionRequest {
    pub amount: u64,
    pub currency: String,
    pub payment_method: String,
    pub terminal_id: String,
    pub merchant_id: String,
    #[serde(default)]
    pub capture_mode: CaptureMode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CaptureMode {
    #[default]
    Auto,
    Manual,
}

/// Builds the connector's transaction. `card` is the decrypted card: the request only carries
/// `encrypted_card_data`, which is decrypted outside the connector (HSM, Stage 5).
pub fn to_host_transaction(transaction_id: &str, request: &TransactionRequest, card: Card)
    -> Result<Transaction, String> {
    if request.payment_method != "CARD" {
        return Err(format!("{} payments don't go to an ISO 8583 card host", request.payment_method));
    }
    Ok(Transaction {
        transaction_id: transaction_id.into(),
        // AUTO captures in one step (0200); MANUAL authorizes now and captures later (0100).
        kind: match request.capture_mode {
            CaptureMode::Auto => TransactionKind::Purchase,
            CaptureMode::Manual => TransactionKind::Authorization,
        },
        amount_minor: request.amount,
        currency: request.currency.clone(),
        merchant_id: request.merchant_id.clone(),
        terminal_id: request.terminal_id.clone(),
        card,
    })
}

/// `TransactionStatus` values a host exchange can lead to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Captured,
    Authorized,
    Failed,
    /// The host may or may not have acted on it; resolved by a reversal or a status inquiry, never by retrying.
    Pending,
}

/// The spec's `Error` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    pub error_code: &'static str,
    pub error_message: String,
    pub error_category: &'static str,
    pub retryable: bool,
}

/// What goes back into the unified transaction: status, `method_reference`, `auth_code` and, only when
/// FAILED, `error` (as the spec requires).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

pub fn outcome(kind: &TransactionKind, result: &Result<HostResponse, HostError>) -> Outcome {
    let failed = |error_code, category: &'static str, retryable, message: String, reference: Option<String>| Outcome {
        status: Status::Failed,
        method_reference: reference,
        auth_code: None,
        error: Some(ErrorBody { error_code, error_message: message, error_category: category, retryable }),
    };
    match result {
        Ok(HostResponse { decision: Decision::Approved { authorization_code }, host_reference, .. }) => Outcome {
            status: if *kind == TransactionKind::Authorization { Status::Authorized } else { Status::Captured },
            method_reference: host_reference.clone(),
            auth_code: Some(authorization_code.clone()).filter(|c| !c.is_empty()),
            error: None,
        },
        Ok(HostResponse { decision: Decision::Declined { category }, response_code, host_reference }) => {
            let (cat, retryable) = match category {
                DeclineCategory::Soft => ("SOFT_DECLINE", true),
                DeclineCategory::Hard => ("HARD_DECLINE", false),
            };
            let code = if response_code == "51" { "INSUFFICIENT_FUNDS" } else { "ISSUER_DECLINED" };
            failed(code, cat, retryable, format!("declined by the issuer (response code {response_code})"),
                   host_reference.clone())
        }
        // Never reached the host, so nothing happened there: a clean failure, safe to retry.
        Err(HostError::Unavailable(why)) => {
            failed("INTERNAL_ERROR", "SYSTEM_ERROR", true, format!("acquirer host unavailable: {why}"), None)
        }
        // The host may have approved it: not FAILED, or the merchant could charge the customer twice.
        Err(HostError::Timeout | HostError::ConnectionLost(_) | HostError::Protocol(_)) => {
            Outcome { status: Status::Pending, method_reference: None, auth_code: None, error: None }
        }
    }
}
