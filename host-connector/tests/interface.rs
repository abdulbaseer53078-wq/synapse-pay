//! Task 4.1 acceptance: the interface works through `dyn HostConnector`, and the mock behaves like a host.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use host_connector::mock::MockHostConnector;
use host_connector::{Card, Decision, DeclineCategory, HostConnector, HostError, HostResponse, HostState,
                     HostStatus, RequestContext, Transaction, TransactionKind};

/// The mock never waits, so one poll completes it; no async runtime needed for these tests.
fn ready<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("mock futures complete immediately"),
    }
}

fn purchase(id: &str) -> Transaction {
    Transaction {
        transaction_id: id.into(),
        kind: TransactionKind::Purchase,
        amount_minor: 50_000,
        currency: "INR".into(),
        merchant_id: "merch_1001".into(),
        terminal_id: "term_blr_001".into(),
        card: Card { pan: "4111111111111111".into(), expiry: "2812".into() },
    }
}

fn ctx() -> RequestContext {
    RequestContext::with_timeout(Duration::from_secs(5), "trace-1")
}

/// Core logic sees only the trait, so any acquirer (or the mock) can be plugged in.
fn send(host: &dyn HostConnector, txn: &Transaction) -> Result<HostResponse, HostError> {
    ready(host.send_transaction(&ctx(), txn))
}

#[test]
fn mock_answers_in_script_order_then_approves() {
    let mock = MockHostConnector::new();
    let soft = HostResponse {
        decision: Decision::Declined { category: DeclineCategory::Soft },
        response_code: "91".into(), // issuer unavailable
        host_reference: Some("531110000001".into()),
    };
    mock.respond_with(Ok(soft.clone())).respond_with(Err(HostError::Unavailable("connection refused".into())));

    assert_eq!(send(&mock, &purchase("txn_1")), Ok(soft));
    assert_eq!(send(&mock, &purchase("txn_2")), Err(HostError::Unavailable("connection refused".into())));
    assert_eq!(send(&mock, &purchase("txn_3")), Ok(MockHostConnector::approval()));
    let ids: Vec<_> = mock.received().into_iter().map(|t| t.transaction_id).collect();
    assert_eq!(ids, ["txn_1", "txn_2", "txn_3"]);
}

#[test]
fn an_expired_deadline_times_out() {
    let mock = MockHostConnector::new();
    let late = RequestContext::with_timeout(Duration::ZERO, "trace-2");
    let result = ready(mock.send_transaction(&late, &purchase("txn_1")));
    assert_eq!(result, Err(HostError::Timeout));
    assert_eq!(mock.received().len(), 1, "a timed-out request may still have reached the host");
}

#[test]
fn only_undelivered_failures_are_safe_to_retry() {
    assert!(!HostError::Unavailable("down".into()).outcome_unknown());
    assert!(HostError::Timeout.outcome_unknown());
    assert!(HostError::Protocol("bad MTI".into()).outcome_unknown());
}

#[test]
fn health_is_reported_not_raised() {
    let mock = MockHostConnector::new();
    assert_eq!(ready(mock.check_health()).state, HostState::Up);
    mock.set_status(HostStatus { state: HostState::Down, latency: None });
    assert_eq!(ready(mock.check_health()).state, HostState::Down);
}

#[test]
fn several_acquirers_behind_one_interface() {
    let hosts: Vec<Box<dyn HostConnector>> = vec![Box::new(MockHostConnector::new()), Box::new(MockHostConnector::new())];
    for host in &hosts {
        assert!(matches!(send(host.as_ref(), &purchase("txn_1")), Ok(HostResponse { decision: Decision::Approved { .. }, .. })));
    }
}

#[test]
fn debug_output_hides_the_card_number() {
    let shown = format!("{:?}", purchase("txn_1"));
    assert!(!shown.contains("4111111111111111") && !shown.contains("2812"), "{shown}");
    assert!(shown.contains("****1111"), "{shown}");
}
