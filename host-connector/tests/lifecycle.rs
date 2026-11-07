//! Task 4.4 acceptance: a transaction in the API's unified JSON shape goes over a real mTLS connection to a
//! simulated acquirer host as ISO 8583, and the host's reply comes back as CAPTURED or FAILED.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use host_connector::framing::{Framing, LengthHeader};
use host_connector::iso_host::{IsoHostConfig, IsoHostConnector};
use host_connector::link::{Link, LinkConfig};
use host_connector::unified::{outcome, to_host_transaction, Status, TransactionRequest};
use host_connector::{Card, HostConnector, HostError, RequestContext};
use iso8583::{pack, unpack, Dictionary, Iso8583Message};
use rcgen::{BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{self, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

const DIALECT: &str = include_str!("../../iso8583/dialects/synthetic-host.json");
const FRAMING: Framing = Framing { header: LengthHeader::Binary2, max_len: 8_192 };

/// A unified transaction as the API receives it (spec TransactionRequest, CARD).
fn api_request(amount: u64, capture_mode: &str) -> TransactionRequest {
    serde_json::from_value(serde_json::json!({
        "idempotency_key": "0b8e6c1a-4f2d-4a9e-8c3b-1d2e3f4a5b6c",
        "amount": amount,
        "currency": "INR",
        "payment_method": "CARD",
        "method_details": { "encrypted_card_data": "hQEMA0x7cX9K", "card_expiry": "08/28", "card_network": "VISA" },
        "terminal_id": "TERM0001",
        "merchant_id": "MERCHANT0000001",
        "capture_mode": capture_mode
    })).unwrap()
}

fn card() -> Card {
    Card { pan: "4111111111111111".into(), expiry: "2808".into() }
}

// --- certificates ------------------------------------------------------------------------------------------

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    Ca { cert: params.self_signed(&key).unwrap(), key }
}

fn leaf(ca: &Ca, name: &str, usage: ExtendedKeyUsagePurpose) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    params.extended_key_usages = vec![usage];
    (params.signed_by(&key, &ca.cert, &ca.key).unwrap().pem(), key.serialize_pem())
}

fn link_config(addr: &str, ca: &Ca) -> LinkConfig {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("lifecycle-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = leaf(ca, "synapsepay-client", ExtendedKeyUsagePurpose::ClientAuth);
    std::fs::write(dir.join("ca.pem"), ca.cert.pem()).unwrap();
    std::fs::write(dir.join("client.pem"), cert).unwrap();
    std::fs::write(dir.join("client-key.pem"), key).unwrap();
    let mut config = LinkConfig::new(addr, "localhost", dir.join("ca.pem"), dir.join("client.pem"), dir.join("client-key.pem"));
    config.initial_backoff = Duration::from_millis(50);
    config
}

// --- simulated acquirer host -------------------------------------------------------------------------------

/// How the host treats requests: answer each with a DE 39 code, hold `n` and answer them in reverse order,
/// or never answer.
#[derive(Clone)]
enum Behaviour {
    Answer(fn(&Iso8583Message) -> &'static str),
    ReverseAfter(usize, &'static str),
    Silent,
}

/// What the host received: (MTI, field number, value) for every request.
type Seen = Arc<Mutex<Vec<(String, Vec<(u8, String)>)>>>;

fn response(req: &Iso8583Message, code: &str, d: &Dictionary) -> Vec<u8> {
    let mti = format!("{:04}", req.mti().parse::<u16>().unwrap() + 10);
    let mut resp = Iso8583Message::new(&mti).unwrap();
    for field in [3, 4, 7, 11, 37, 41, 49] {
        if let Some(v) = req.get(field) {
            resp.set(field, v.to_vec()).unwrap();
        }
    }
    resp.set(39, code.as_bytes().to_vec()).unwrap();
    if code == "00" {
        resp.set(38, &b"AUTH42"[..]).unwrap();
    }
    let mut frame = Vec::new();
    FRAMING.encode(&pack(&resp, d).unwrap(), &mut frame).unwrap();
    frame
}

async fn acquirer_host(ca: &Ca, behaviour: Behaviour) -> (String, Seen) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert.der().clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().unwrap();
    let (cert, key) = leaf(ca, "localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12]).unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from_pem_slice(cert.as_bytes()).unwrap()],
                          PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap())
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = Seen::default();
    let record = seen.clone();
    tokio::spawn(async move {
        let d = Dictionary::from_json(DIALECT).unwrap();
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let (mut buf, mut held, mut chunk) = (Vec::new(), Vec::new(), [0u8; 4096]);
        while let Ok(n @ 1..) = tls.read(&mut chunk).await {
            buf.extend_from_slice(&chunk[..n]);
            while let Some((frame, used)) = FRAMING.decode(&buf).unwrap() {
                let frame = frame.to_vec();
                buf.drain(..used);
                let req = unpack(&frame, &d).unwrap();
                let fields = req.fields().map(|f| (f, req.get_str(f).unwrap_or("").to_owned())).collect();
                record.lock().await.push((req.mti().to_owned(), fields));
                match &behaviour {
                    Behaviour::Answer(code) => tls.write_all(&response(&req, code(&req), &d)).await.unwrap(),
                    Behaviour::ReverseAfter(n, code) => {
                        held.push(response(&req, code, &d));
                        if held.len() == *n {
                            for frame in held.drain(..).rev() {
                                tls.write_all(&frame).await.unwrap();
                            }
                        }
                    }
                    Behaviour::Silent => {}
                }
            }
        }
    });
    (addr, seen)
}

async fn connector(addr: &str, ca: &Ca) -> IsoHostConnector {
    let (link, events) = Link::start(link_config(addr, ca)).unwrap();
    assert!(link.wait_up(Duration::from_secs(5)).await, "link didn't come up");
    let config = IsoHostConfig::new(Dictionary::from_json(DIALECT).unwrap(), FRAMING);
    IsoHostConnector::new(link, events, config)
}

fn ctx(timeout_ms: u64) -> RequestContext {
    RequestContext::with_timeout(Duration::from_millis(timeout_ms), "trace")
}

// --- tests -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn approved_purchase_from_the_api_is_captured() {
    let ca = ca();
    let (addr, seen) = acquirer_host(&ca, Behaviour::Answer(|_| "00")).await;
    let host = connector(&addr, &ca).await;

    let request = api_request(50_000, "AUTO");
    let txn = to_host_transaction("txn_01", &request, card()).unwrap();
    let result = host.send_transaction(&ctx(5_000), &txn).await;
    let out = outcome(&txn.kind, &result);

    assert_eq!(out.status, Status::Captured);
    assert_eq!(out.auth_code.as_deref(), Some("AUTH42"));
    assert!(out.error.is_none());

    let seen = seen.lock().await;
    let (mti, fields) = &seen[0];
    let field = |n| fields.iter().find(|(f, _)| *f == n).map(|(_, v)| v.as_str());
    assert_eq!(mti, "0200", "AUTO capture is a purchase");
    assert_eq!((field(2), field(4), field(49)), (Some("4111111111111111"), Some("000000050000"), Some("356")));
    assert_eq!((field(41), field(42)), (Some("TERM0001"), Some("MERCHANT0000001")));
    assert_eq!(field(11).map(str::len), Some(6), "STAN");
    assert_eq!(out.method_reference.as_deref(), field(37), "RRN comes back as method_reference");
}

#[tokio::test]
async fn declines_map_to_failed_with_the_spec_error_codes() {
    let ca = ca();
    // The host declines by amount, so each request gets a different DE 39.
    let (addr, _) = acquirer_host(&ca, Behaviour::Answer(|req| match req.get_str(4).unwrap() {
        "000000000051" => "51",
        "000000000005" => "05",
        _ => "91",
    })).await;
    let host = connector(&addr, &ca).await;

    for (amount, code, category, retryable) in [(51, "INSUFFICIENT_FUNDS", "HARD_DECLINE", false),
                                                (5, "ISSUER_DECLINED", "HARD_DECLINE", false),
                                                (91, "ISSUER_DECLINED", "SOFT_DECLINE", true)] {
        let txn = to_host_transaction("txn", &api_request(amount, "AUTO"), card()).unwrap();
        let out = outcome(&txn.kind, &host.send_transaction(&ctx(5_000), &txn).await);
        assert_eq!(out.status, Status::Failed, "amount {amount}");
        let error = out.error.unwrap();
        assert_eq!((error.error_code, error.error_category, error.retryable), (code, category, retryable));
        assert!(!error.error_message.contains("4111"), "no PAN in errors");
    }
}

#[tokio::test]
async fn manual_capture_is_an_authorization() {
    let ca = ca();
    let (addr, seen) = acquirer_host(&ca, Behaviour::Answer(|_| "00")).await;
    let host = connector(&addr, &ca).await;
    let txn = to_host_transaction("txn", &api_request(1_000, "MANUAL"), card()).unwrap();
    let out = outcome(&txn.kind, &host.send_transaction(&ctx(5_000), &txn).await);
    assert_eq!(out.status, Status::Authorized);
    assert_eq!(seen.lock().await[0].0, "0100");
}

#[tokio::test]
async fn concurrent_transactions_get_their_own_responses_even_out_of_order() {
    let ca = ca();
    let (addr, _) = acquirer_host(&ca, Behaviour::ReverseAfter(3, "00")).await;
    let host = connector(&addr, &ca).await;
    let txns: Vec<_> = [100, 200, 300].into_iter()
        .map(|amount| to_host_transaction("txn", &api_request(amount, "AUTO"), card()).unwrap()).collect();
    let ctx = ctx(5_000);
    let (a, b, c) = tokio::join!(host.send_transaction(&ctx, &txns[0]),
                                 host.send_transaction(&ctx, &txns[1]),
                                 host.send_transaction(&ctx, &txns[2]));
    // Each response echoes its request's RRN, which embeds that request's STAN, so a mix-up shows here.
    let refs: Vec<String> = [a, b, c].into_iter().map(|r| r.unwrap().host_reference.unwrap()).collect();
    assert_eq!(refs.iter().collect::<std::collections::HashSet<_>>().len(), 3, "three distinct responses");
}

#[tokio::test]
async fn no_answer_is_pending_not_failed() {
    let ca = ca();
    let (addr, _) = acquirer_host(&ca, Behaviour::Silent).await;
    let host = connector(&addr, &ca).await;
    let txn = to_host_transaction("txn", &api_request(1_000, "AUTO"), card()).unwrap();
    let result = host.send_transaction(&ctx(300), &txn).await;
    assert_eq!(result, Err(HostError::Timeout));
    let out = outcome(&txn.kind, &result);
    assert_eq!((out.status, out.error), (Status::Pending, None), "the host may have approved it");
}

#[tokio::test]
async fn unreachable_host_fails_cleanly_without_sending() {
    let ca = ca();
    let (link, events) = Link::start(link_config("127.0.0.1:1", &ca)).unwrap(); // nothing listens there
    let host = IsoHostConnector::new(link, events, IsoHostConfig::new(Dictionary::from_json(DIALECT).unwrap(), FRAMING));
    let txn = to_host_transaction("txn", &api_request(1_000, "AUTO"), card()).unwrap();
    let result = host.send_transaction(&ctx(1_000), &txn).await;
    assert!(matches!(result, Err(HostError::Unavailable(_))), "{result:?}");
    let error = outcome(&txn.kind, &result).error.unwrap();
    assert_eq!((error.error_code, error.retryable), ("INTERNAL_ERROR", true));
}

#[test]
fn only_card_payments_go_to_a_card_host() {
    let mut request = api_request(1_000, "AUTO");
    request.payment_method = "UPI".into();
    assert!(to_host_transaction("txn", &request, card()).is_err());
}
