//! Task 4.8 acceptance: the Host Connector against the independent Python mock acquirer
//! (mock_host/mock_host.py) over mutual TLS: approvals, declines, timeouts and dropped connections.
//!
//! Needs Python 3 on PATH (`python3`, or `python` on Windows; override with PYTHON).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use host_connector::audit::{AuditRecord, AuditSink, Direction};
use host_connector::framing::{Framing, LengthHeader};
use host_connector::iso_host::{IsoHostConfig, IsoHostConnector};
use host_connector::link::{Link, LinkConfig};
use host_connector::{Card, Decision, HostConnector, HostError, RequestContext, Transaction, TransactionKind};
use iso8583::Dictionary;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};

const DIALECT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../iso8583/dialects/synthetic-host.json");
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/mock_host/mock_host.py");
const FRAMING: Framing = Framing { header: LengthHeader::Binary2, max_len: 8_192 };

// The mock's scenarios, keyed by amount in minor units.
const APPROVE: u64 = 15_000;
const DECLINE: u64 = 5_100;
const TIMEOUT: u64 = 2_000;
const DROP: u64 = 9_900;

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // Distinct names: OpenSSL won't chain a certificate whose subject equals its issuer's (rcgen's default).
    params.distinguished_name.push(DnType::CommonName, "SynapsePay Test CA");
    Ca { cert: params.self_signed(&key).unwrap(), key }
}

/// Writes `<name>.pem` and `<name>-key.pem` for a certificate issued by `ca`.
fn issue(ca: &Ca, dir: &Path, name: &str, san: &str, usage: ExtendedKeyUsagePurpose) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![usage];
    params.distinguished_name.push(DnType::CommonName, san);
    std::fs::write(dir.join(format!("{name}.pem")), params.signed_by(&key, &ca.cert, &ca.key).unwrap().pem()).unwrap();
    std::fs::write(dir.join(format!("{name}-key.pem")), key.serialize_pem()).unwrap();
}

/// The running mock; killed when dropped.
struct MockHost {
    child: Child,
    addr: String,
    dir: PathBuf,
}

impl Drop for MockHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_mock() -> MockHost {
    start_mock_with(&[])
}

fn start_mock_with(extra_args: &[&str]) -> MockHost {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("mock-host-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = ca();
    std::fs::write(dir.join("ca.pem"), ca.cert.pem()).unwrap();
    issue(&ca, &dir, "host", "localhost", ExtendedKeyUsagePurpose::ServerAuth);
    issue(&ca, &dir, "client", "synapsepay-client", ExtendedKeyUsagePurpose::ClientAuth);

    let python = std::env::var("PYTHON").unwrap_or_else(|_| if cfg!(windows) { "python" } else { "python3" }.into());
    let mut child = Command::new(&python)
        .args([SCRIPT, "--dialect", DIALECT])
        .arg("--cert").arg(dir.join("host.pem"))
        .arg("--key").arg(dir.join("host-key.pem"))
        .arg("--client-ca").arg(dir.join("ca.pem"))
        .args(extra_args)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("can't run {python} (set PYTHON to a Python 3): {e}"));
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    out.read_line(&mut first).unwrap();
    let port = first.trim().strip_prefix("LISTENING ").unwrap_or_else(|| panic!("mock didn't start: {first:?}"));
    // Keep draining the mock's log (MTI, STAN, outcome; never card data) so failures are explainable.
    std::thread::spawn(move || out.lines().map_while(Result::ok).for_each(|l| eprintln!("[mock] {l}")));
    MockHost { addr: format!("127.0.0.1:{port}"), child, dir }
}

/// Keeps audit records in memory.
#[derive(Default)]
struct Recorder(Mutex<Vec<AuditRecord>>);

impl AuditSink for Recorder {
    fn record(&self, record: &AuditRecord) -> std::io::Result<()> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
}

async fn connector(mock: &MockHost) -> IsoHostConnector {
    connector_auditing(mock, None).await
}

async fn connector_auditing(mock: &MockHost, audit: Option<Arc<Recorder>>) -> IsoHostConnector {
    let d = &mock.dir;
    let mut link = LinkConfig::new(&mock.addr, "localhost", d.join("ca.pem"), d.join("client.pem"), d.join("client-key.pem"));
    link.initial_backoff = Duration::from_millis(50);
    let (link, events) = Link::start(link).unwrap();
    assert!(link.wait_up(Duration::from_secs(5)).await, "link to the mock didn't come up: {:?}", link.state());
    let dictionary = Dictionary::from_json(&std::fs::read_to_string(DIALECT).unwrap()).unwrap();
    let mut config = IsoHostConfig::new(dictionary, FRAMING);
    config.audit = audit.map(|r| r as Arc<dyn AuditSink>);
    IsoHostConnector::new(link, events, config)
}

fn auth(amount_minor: u64) -> Transaction {
    Transaction {
        transaction_id: format!("txn_mock_{amount_minor}"),
        kind: TransactionKind::Authorization, // ISO 8583 0100
        amount_minor,
        currency: "INR".into(),
        merchant_id: "MERCHANT0000001".into(),
        terminal_id: "TERM0001".into(),
        card: Card { pan: "4111111111111111".into(), expiry: "2812".into() },
    }
}

fn ctx(timeout: Duration) -> RequestContext {
    RequestContext::with_timeout(timeout, "mock-host-test")
}

#[tokio::test(flavor = "multi_thread")]
async fn approval() {
    let mock = start_mock();
    let host = connector(&mock).await;
    let resp = host.send_transaction(&ctx(Duration::from_secs(5)), &auth(APPROVE)).await.unwrap();
    assert_eq!(resp.response_code, "00");
    assert!(matches!(resp.decision, Decision::Approved { ref authorization_code } if !authorization_code.is_empty()));
}

#[tokio::test(flavor = "multi_thread")]
async fn decline() {
    let mock = start_mock();
    let host = connector(&mock).await;
    let resp = host.send_transaction(&ctx(Duration::from_secs(5)), &auth(DECLINE)).await.unwrap();
    assert_eq!(resp.response_code, "51");
    assert!(matches!(resp.decision, Decision::Declined { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_gives_up_at_the_deadline_with_the_outcome_unknown() {
    let mock = start_mock(); // answers this amount only after 20 s
    let host = connector(&mock).await;
    let started = Instant::now();
    let err = host.send_transaction(&ctx(Duration::from_secs(2)), &auth(TIMEOUT)).await.unwrap_err();
    assert_eq!(err, HostError::Timeout);
    assert!(err.outcome_unknown(), "the host may have approved it: reverse, don't retry");
    assert!(started.elapsed() < Duration::from_secs(3), "gave up at the 2 s deadline, not after 20 s");

    // The connector still works afterwards.
    assert!(host.link().wait_up(Duration::from_secs(5)).await);
    let resp = host.send_transaction(&ctx(Duration::from_secs(5)), &auth(APPROVE)).await.unwrap();
    assert_eq!(resp.response_code, "00");
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_connection_fails_cleanly_then_reconnects() {
    let mock = start_mock();
    let host = connector(&mock).await;
    let started = Instant::now();
    let err = host.send_transaction(&ctx(Duration::from_secs(15)), &auth(DROP)).await.unwrap_err();
    assert!(err.outcome_unknown(), "sent, then the connection died: outcome unknown ({err:?})");
    assert!(started.elapsed() < Duration::from_secs(15), "noticed the drop, didn't wait out the deadline");

    assert!(host.link().wait_up(Duration::from_secs(5)).await, "link reconnects after the drop");
    let resp = host.send_transaction(&ctx(Duration::from_secs(5)), &auth(APPROVE)).await.unwrap();
    assert_eq!(resp.response_code, "00");
}

#[tokio::test(flavor = "multi_thread")]
async fn network_echo() {
    let mock = start_mock();
    let host = connector(&mock).await;
    host.echo(&ctx(Duration::from_secs(5))).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn host_down_is_unavailable_and_safe_to_retry() {
    let mut mock = start_mock();
    let host = connector(&mock).await;
    mock.child.kill().unwrap();
    mock.child.wait().unwrap();
    let mut last = None;
    for _ in 0..50 { // until the link notices the host is gone
        match host.send_transaction(&ctx(Duration::from_secs(2)), &auth(APPROVE)).await {
            Err(e @ HostError::Unavailable(_)) => { last = Some(e); break; }
            other => last = Some(other.unwrap_err()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let err = last.unwrap();
    assert!(matches!(err, HostError::Unavailable(_)) && !err.outcome_unknown(), "{err:?}");
}

/// Task 4.7 end to end: each message on the wire gets a redacted record under its transaction_id.
#[tokio::test(flavor = "multi_thread")]
async fn every_message_is_audited_with_the_pan_masked() {
    let mock = start_mock();
    let recorder = Arc::new(Recorder::default());
    let host = connector_auditing(&mock, Some(recorder.clone())).await;
    host.send_transaction(&ctx(Duration::from_secs(5)), &auth(APPROVE)).await.unwrap();

    let records = recorder.0.lock().unwrap().clone();
    let summary: Vec<_> = records.iter().map(|r| (r.direction, r.mti.as_deref(), r.transaction_id.as_str())).collect();
    assert_eq!(summary, [(Direction::Outbound, Some("0100"), "txn_mock_15000"),
                         (Direction::Inbound, Some("0110"), "txn_mock_15000")]);
    assert_eq!(records[0].fields[&2], "411111******1111");
    let json = serde_json::to_string(&records).unwrap();
    assert!(!json.contains("4111111111111111") && !json.contains("34313131313131313131313131313131"), "{json}");
}

/// Task 4.5: a response timeout kills the connection, so the host's late reply can never be delivered (or
/// mistaken for a newer request's), and the link comes back on a fresh socket.
#[tokio::test(flavor = "multi_thread")]
async fn a_timeout_kills_the_connection_so_the_late_reply_never_arrives() {
    let mock = start_mock_with(&["--sleep", "1"]); // the late reply comes 1 s after the request
    let recorder = Arc::new(Recorder::default());
    let host = connector_auditing(&mock, Some(recorder.clone())).await;
    let err = host.send_transaction(&ctx(Duration::from_millis(300)), &auth(TIMEOUT)).await.unwrap_err();
    assert_eq!(err, HostError::Timeout);

    tokio::time::sleep(Duration::from_millis(1_500)).await; // past the moment the mock answers
    assert!(host.link().wait_up(Duration::from_secs(5)).await, "reconnected");
    let inbound = recorder.0.lock().unwrap().iter().filter(|r| r.direction == Direction::Inbound).count();
    assert_eq!(inbound, 0, "the late 0110 went to the killed socket, not to us");
    let resp = host.send_transaction(&ctx(Duration::from_secs(5)), &auth(APPROVE)).await.unwrap();
    assert_eq!(resp.response_code, "00");
}
