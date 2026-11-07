//! Step 14.9: a fleet that has given up on one host must never let that host's late reply settle anything.
//!
//! Host A answers after 2 s; the transaction's deadline is 300 ms, so the fleet moves to B, which answers at
//! once. A's approval eventually reaches a socket the connector already tore down — a connection that missed its
//! deadline is not trusted, exactly because its next bytes could be a reply to a request nobody is waiting for.
//! The test pins three things: B is the host that answered, the customer sees one approval, and the audit log has
//! one inbound response for the transaction, with no `unmatched-stan-*` record that a late reply could hide in.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use card_service::fleet::Fleet;
use host_connector::audit::{AuditSink, JsonLines};
use host_connector::framing::{Framing, LengthHeader};
use host_connector::iso_host::IsoHostConfig;
use host_connector::link::LinkConfig;
use host_connector::pool::{IsoHostPool, PoolConfig};
use host_connector::stan::StanSource;
use host_connector::{Card, Decision, HostConnector, RequestContext, Transaction, TransactionKind};
use iso8583::{pack, unpack, Dictionary, Iso8583Message};
use rcgen::{BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{self, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

const DIALECT: &str = include_str!("../../iso8583/dialects/synthetic-host.json");
const FRAMING: Framing = Framing { header: LengthHeader::Binary2, max_len: 8_192 };

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

/// The card service's own credentials: one client certificate, accepted by every host in the fleet.
fn client_credentials(dir: &Path, ca: &Ca) -> (PathBuf, PathBuf, PathBuf) {
    std::fs::create_dir_all(dir).unwrap();
    let (cert, key) = leaf(ca, "synapsepay-card-service", ExtendedKeyUsagePurpose::ClientAuth);
    let (ca_path, cert_path, key_path) = (dir.join("ca.pem"), dir.join("client.pem"), dir.join("client-key.pem"));
    std::fs::write(&ca_path, ca.cert.pem()).unwrap();
    std::fs::write(&cert_path, cert).unwrap();
    std::fs::write(&key_path, key).unwrap();
    (ca_path, cert_path, key_path)
}

fn respond(request: &Iso8583Message, dictionary: &Dictionary) -> Vec<u8> {
    let mti = format!("{:04}", request.mti().parse::<u16>().unwrap() + 10);
    let mut response = Iso8583Message::new(&mti).unwrap();
    for field in [3, 4, 7, 11, 37, 41, 49, 70] {
        if let Some(value) = request.get(field) {
            response.set(field, value.to_vec()).unwrap();
        }
    }
    response.set(39, &b"00"[..]).unwrap();
    response.set(38, &b"AUTH01"[..]).unwrap();
    let mut frame = Vec::new();
    FRAMING.encode(&pack(&response, dictionary).unwrap(), &mut frame).unwrap();
    frame
}

#[derive(Default)]
struct HostStats {
    /// Non-echo requests the host received. One per transaction, never a retry or a reversal.
    purchases: AtomicUsize,
}

/// An mTLS ISO 8583 host that sleeps `delay` before answering a purchase. Echoes are answered at once so a
/// pool's keep-alive never waits on the artificial delay.
async fn host(ca: &Ca, delay: Duration) -> (String, Arc<HostStats>) {
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
    let stats = Arc::new(HostStats::default());
    let host_stats = stats.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            let stats = host_stats.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let (mut reader, mut writer) = tokio::io::split(tls);
                let dictionary = Dictionary::from_json(DIALECT).unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n @ 1..) = reader.read(&mut chunk).await else { return };
                    buf.extend_from_slice(&chunk[..n]);
                    while let Ok(Some((frame, used))) = FRAMING.decode(&buf) {
                        let Ok(request) = unpack(frame, &dictionary) else { return };
                        let is_echo = request.mti() == "0800";
                        if !is_echo {
                            stats.purchases.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(delay).await;
                        }
                        let reply = respond(&request, &dictionary);
                        if writer.write_all(&reply).await.is_err() {
                            return; // the card service gave up and closed the socket: a late reply goes nowhere
                        }
                        buf.drain(..used);
                    }
                }
            });
        }
    });
    (addr, stats)
}

fn pool(addr: String, credentials: &(PathBuf, PathBuf, PathBuf), audit: Arc<dyn AuditSink>) -> IsoHostPool {
    let (ca, cert, key) = credentials.clone();
    let mut link = LinkConfig::new(addr, "localhost", ca, cert, key);
    link.initial_backoff = Duration::from_millis(50);
    link.max_backoff = Duration::from_millis(100);
    let mut iso = IsoHostConfig::new(Dictionary::from_json(DIALECT).unwrap(), FRAMING);
    iso.audit = Some(audit);
    IsoHostPool::start(link, iso, PoolConfig { size: 1, ..PoolConfig::default() }).unwrap()
}

fn purchase() -> Transaction {
    Transaction {
        transaction_id: "txn_demux".into(),
        kind: TransactionKind::Purchase,
        amount_minor: 50_000,
        currency: "INR".into(),
        merchant_id: "MERCHANT0000001".into(),
        terminal_id: "TERM0001".into(),
        card: Card { pan: "4111111111111111".into(), expiry: "2808".into() },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_late_reply_is_discarded() {
    let ca = ca();
    let dir = std::env::temp_dir().join(format!("demux-{}", std::process::id()));
    let credentials = client_credentials(&dir, &ca);
    let (a_addr, a_stats) = host(&ca, Duration::from_secs(2)).await;
    let (b_addr, b_stats) = host(&ca, Duration::ZERO).await;

    let audit_path = dir.join("iso-audit.jsonl");
    let audit_file = std::fs::OpenOptions::new().create(true).append(true).open(&audit_path).unwrap();
    let audit: Arc<dyn AuditSink> = Arc::new(JsonLines::new(audit_file));

    let mut pools = HashMap::new();
    pools.insert("acquirer_a".to_string(), Arc::new(pool(a_addr, &credentials, audit.clone())));
    pools.insert("acquirer_b".to_string(), Arc::new(pool(b_addr, &credentials, audit.clone())));
    let fleet = Fleet::new(pools, Arc::new(StanSource::single()));
    for pool in fleet.pools.values() {
        assert_eq!(pool.wait_ready(Duration::from_secs(5)).await, 1);
    }

    // A gets 300 ms and is slow; the fleet must spend the rest of its budget on B rather than wait for A.
    let mut ctx = RequestContext::with_timeout(Duration::from_millis(300), "txn_demux");
    ctx.host_hint = vec!["acquirer_a".into(), "acquirer_b".into()];
    let response = fleet.send_transaction(&ctx, &purchase()).await.unwrap();

    assert_eq!(response.host_used, "acquirer_b");
    assert_eq!(response.decision, Decision::Approved { authorization_code: "AUTH01".into() });
    assert_eq!(a_stats.purchases.load(Ordering::SeqCst), 1);
    assert_eq!(b_stats.purchases.load(Ordering::SeqCst), 1);

    // Wait for A's late reply to hit the socket.
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    // Exactly one request per host: a late reply must never be mistaken for a reason to retry or reverse.
    assert_eq!(a_stats.purchases.load(Ordering::SeqCst), 1, "A's late reply must not trigger a second attempt");
    assert_eq!(b_stats.purchases.load(Ordering::SeqCst), 1);

    let log = std::fs::read_to_string(&audit_path).unwrap();
    let records: Vec<serde_json::Value> =
        log.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    let inbound_for_txn = records.iter()
        .filter(|r| r["transaction_id"] == "txn_demux" && r["direction"].as_str() == Some("inbound"))
        .count();
    // B's approval only. A's reply never became an inbound record: its connection was torn down at the deadline,
    // which discards it earlier than the unmatched-STAN path ever could.
    assert_eq!(inbound_for_txn, 1, "only the host that answered produced a response: {log}");
    assert!(!log.contains("unmatched-stan-"),
            "a timed-out socket must be gone before a late reply can be recorded as unmatched: {log}");
}
