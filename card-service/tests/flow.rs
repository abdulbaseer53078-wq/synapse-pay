//! The card flow against the scripted in-memory host: approvals, declines, timeouts and reversals.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use card_service::fleet::Fleet;
use card_service::flow::{CardFlow, CardRequest, FlowError, Kind, Reversal, Timeouts};
use card_service::hsm::{format0_pin_block, SimHsm};
use card_service::http::AppState;
use host_connector::mock::MockHostConnector;
use host_connector::unified::Status;
use host_connector::{Decision, DeclineCategory, HostError, HostResponse, TransactionKind};
use http_body_util::BodyExt;
use tower::ServiceExt;

const BDK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PAN: &str = "4111111111111111";

fn hsm() -> SimHsm {
    SimHsm::from_hex(BDK).unwrap()
}

fn request(amount: u64) -> CardRequest {
    CardRequest {
        transaction_id: "txn_test".into(),
        kind: Kind::Purchase,
        amount,
        currency: "INR".into(),
        acquirer_terminal_id: "TERM0001".into(),
        acquirer_merchant_id: "MERCHANT0000001".into(),
        encrypted_card_data: hsm().seal([1; 10], [2; 12], "data", PAN.as_bytes()),
        card_expiry: "08/28".into(),
        pin_block: None,
        emv_data: None,
        card_token: None,
        merchant_id: None,
        host_hint: Vec::new(),
        trace_id: None,
    }
}

fn flow(host: Arc<MockHostConnector>) -> CardFlow {
    let timeouts = Timeouts { reversal_backoff: Duration::from_millis(1), ..Timeouts::default() };
    CardFlow { hsm: Arc::new(hsm()), host, timeouts, vault: None }
}

fn declined(code: &str, category: DeclineCategory) -> Result<HostResponse, HostError> {
    Ok(HostResponse { decision: Decision::Declined { category }, response_code: code.into(), host_reference: None,
                      host_used: String::new() })
}

#[tokio::test]
async fn approval_returns_a_masked_card_and_sends_the_clear_pan_to_the_host_only() {
    let host = Arc::new(MockHostConnector::new());
    let result = flow(host.clone()).process(&request(50_000)).await.unwrap();
    assert_eq!(result.outcome.status, Status::Captured);
    assert_eq!(result.outcome.auth_code.as_deref(), Some("MOCK01"));
    assert_eq!((result.card_bin.as_str(), result.card_last4.as_str()), ("411111", "1111"));
    assert_eq!(result.reversal, Reversal::NotNeeded);
    let sent = host.received();
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].card.pan.as_str(), sent[0].card.expiry.as_str()), (PAN, "2808"));
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains(PAN), "the result must never carry the PAN");
}

#[tokio::test]
async fn manual_capture_is_an_authorization() {
    let host = Arc::new(MockHostConnector::new());
    let mut req = request(50_000);
    req.kind = Kind::Authorization;
    let result = flow(host.clone()).process(&req).await.unwrap();
    assert_eq!(result.outcome.status, Status::Authorized);
    assert_eq!(host.received()[0].kind, TransactionKind::Authorization);
}

#[tokio::test]
async fn decline_is_failed_with_the_issuer_reason() {
    let host = Arc::new(MockHostConnector::new());
    host.respond_with(declined("51", DeclineCategory::Hard));
    let result = flow(host).process(&request(50_000)).await.unwrap();
    assert_eq!(result.outcome.status, Status::Failed);
    let error = result.outcome.error.unwrap();
    assert_eq!((error.error_code, error.retryable), ("INSUFFICIENT_FUNDS", false));
}

#[tokio::test]
async fn timeout_is_reversed_and_reported_retryable() {
    let host = Arc::new(MockHostConnector::new());
    host.respond_with(Err(HostError::Timeout)); // the purchase; the reversal is then approved by default
    let result = flow(host.clone()).process(&request(50_000)).await.unwrap();
    assert_eq!(result.reversal, Reversal::Reversed);
    assert_eq!(result.outcome.status, Status::Failed);
    let error = result.outcome.error.unwrap();
    assert_eq!((error.error_code, error.error_category, error.retryable), ("HOST_TIMEOUT", "SYSTEM_ERROR", true));
    let sent = host.received();
    assert_eq!(sent[1].kind, TransactionKind::Reversal { original_transaction_id: "txn_test".into() });
}

#[tokio::test]
async fn reversal_is_retried_then_left_pending_if_it_never_lands() {
    let host = Arc::new(MockHostConnector::new());
    host.respond_with(Err(HostError::ConnectionLost("cut".into())));
    for _ in 0..3 {
        host.respond_with(Err(HostError::Unavailable("reconnecting".into())));
    }
    let result = flow(host.clone()).process(&request(50_000)).await.unwrap();
    assert_eq!(result.reversal, Reversal::Failed);
    assert_eq!(result.outcome.status, Status::Pending, "unknown outcome: never report FAILED");
    assert!(result.outcome.error.is_none());
    assert_eq!(host.received().len(), 4, "1 purchase + 3 reversal attempts");
}

#[tokio::test]
async fn unavailable_host_fails_cleanly_without_a_reversal() {
    let host = Arc::new(MockHostConnector::new());
    host.respond_with(Err(HostError::Unavailable("down".into())));
    let result = flow(host.clone()).process(&request(50_000)).await.unwrap();
    assert_eq!((result.outcome.status, result.reversal), (Status::Failed, Reversal::NotNeeded));
    assert!(result.outcome.error.unwrap().retryable);
    assert_eq!(host.received().len(), 1);
}

#[tokio::test]
async fn bad_card_data_never_reaches_the_host() {
    let host = Arc::new(MockHostConnector::new());
    let mut req = request(50_000);
    req.encrypted_card_data = SimHsm::new(vec![7; 32]).unwrap().seal([1; 10], [2; 12], "data", PAN.as_bytes());
    assert!(matches!(flow(host.clone()).process(&req).await, Err(FlowError::BadCardData(_))));
    req = request(50_000);
    req.card_expiry = "13/28".into();
    assert!(matches!(flow(host.clone()).process(&req).await, Err(FlowError::BadRequest(_))));
    assert!(host.received().is_empty());
}

#[tokio::test]
async fn pin_block_is_checked() {
    let host = Arc::new(MockHostConnector::new());
    let mut req = request(600_000);
    req.pin_block = Some(hsm().seal([5; 10], [6; 12], "pin", &format0_pin_block("4321", PAN)));
    assert_eq!(flow(host.clone()).process(&req).await.unwrap().outcome.status, Status::Captured);
    req.pin_block = Some("sp1.garbage.garbage".into());
    assert!(matches!(flow(host).process(&req).await, Err(FlowError::BadCardData(_))));
}

#[test]
fn three_ds_outcome_comes_from_the_test_card() {
    use card_service::flow::{AuthenticateRequest, ThreeDs};
    let flow = flow(Arc::new(MockHostConnector::new()));
    let auth = |pan: &str| {
        let req = AuthenticateRequest { transaction_id: "t".into(), amount: 100, currency: "INR".into(),
                                        encrypted_cvv: Some(hsm().seal([3; 10], [4; 12], "cvv", b"123")),
                                        encrypted_card_data: hsm().seal([1; 10], [2; 12], "data", pan.as_bytes()) };
        flow.authenticate(&req).unwrap()
    };
    assert_eq!(auth(PAN).three_ds, ThreeDs::Challenge);
    assert_eq!(auth("4242424242424242").three_ds, ThreeDs::Frictionless);
    assert_eq!(auth("4000000000003238").three_ds, ThreeDs::Rejected);
    assert_eq!(auth(PAN).card_last4, "1111");
    let bad_cvv = AuthenticateRequest { transaction_id: "t".into(), amount: 100, currency: "INR".into(),
                                        encrypted_cvv: Some(hsm().seal([3; 10], [4; 12], "cvv", b"12")),
                                        encrypted_card_data: hsm().seal([1; 10], [2; 12], "data", PAN.as_bytes()) };
    assert!(matches!(flow.authenticate(&bad_cvv), Err(FlowError::BadCardData(_))));
}

#[tokio::test]
async fn http_api() {
    let host = Arc::new(MockHostConnector::new());
    // No pools: the mock answers the transaction, and the fleet-health route reports an empty fleet.
    let app = card_service::http::app(Arc::new(AppState {
        flow: flow(host),
        fleet: Arc::new(Fleet::new(HashMap::new(), Arc::new(host_connector::stan::StanSource::single()))),
    }));
    let body = serde_json::json!({
        "transaction_id": "txn_http", "kind": "PURCHASE", "amount": 50000, "currency": "INR",
        "acquirer_terminal_id": "TERM0001", "acquirer_merchant_id": "MERCHANT0000001",
        "encrypted_card_data": hsm().seal([1; 10], [2; 12], "data", PAN.as_bytes()), "card_expiry": "08/28",
    });
    let resp = app.clone()
        .oneshot(Request::post("/card/transactions").header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(json["status"], "CAPTURED");
    assert_eq!(json["card_last4"], "1111");
    assert_eq!(json["reversal"], "NOT_NEEDED");

    let mut bad = body.clone();
    bad["encrypted_card_data"] = "nope".into();
    let resp = app.clone()
        .oneshot(Request::post("/card/transactions").header("content-type", "application/json")
            .body(Body::from(bad.to_string())).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let resp = app.oneshot(Request::get("/health").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
