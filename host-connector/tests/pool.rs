//! Task 4.6 acceptance: 50 concurrent transactions spread over a pre-warmed pool, one request per connection
//! at a time, each getting its own response; idle connections echo (0800), and a failed echo resets the socket.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use host_connector::framing::{Framing, LengthHeader};
use host_connector::iso_host::IsoHostConfig;
use host_connector::link::LinkConfig;
use host_connector::pool::{IsoHostPool, PoolConfig};
use host_connector::{Card, Decision, HostConnector, HostError, HostState, RequestContext, Transaction, TransactionKind};
use iso8583::{pack, unpack, Dictionary, Iso8583Message};
use rcgen::{BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
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

fn link_config(addr: &str, ca: &Ca) -> LinkConfig {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("pool-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = leaf(ca, "synapsepay-client", ExtendedKeyUsagePurpose::ClientAuth);
    std::fs::write(dir.join("ca.pem"), ca.cert.pem()).unwrap();
    std::fs::write(dir.join("client.pem"), cert).unwrap();
    std::fs::write(dir.join("client-key.pem"), key).unwrap();
    let mut config = LinkConfig::new(addr, "localhost", dir.join("ca.pem"), dir.join("client.pem"), dir.join("client-key.pem"));
    config.initial_backoff = Duration::from_millis(50);
    config.max_backoff = Duration::from_millis(100);
    config
}

#[derive(Default)]
struct HostStats {
    handshakes: AtomicUsize,
    echoes: AtomicUsize,
    /// A request arrived on a connection that already had one unanswered.
    overlaps: AtomicUsize,
    /// A request arrived with a STAN already in flight on any connection.
    duplicate_stans: AtomicUsize,
    in_flight_stans: std::sync::Mutex<std::collections::HashSet<String>>,
    requests_per_connection: Mutex<Vec<usize>>,
}

fn respond(req: &Iso8583Message, d: &Dictionary) -> Vec<u8> {
    let mti = format!("{:04}", req.mti().parse::<u16>().unwrap() + 10);
    let mut resp = Iso8583Message::new(&mti).unwrap();
    for field in [3, 4, 7, 11, 37, 41, 49, 70] {
        if let Some(v) = req.get(field) {
            resp.set(field, v.to_vec()).unwrap();
        }
    }
    resp.set(39, &b"00"[..]).unwrap();
    if let Some(amount) = req.get_str(4) {
        // The auth code encodes this request's amount, so a response delivered to the wrong caller shows.
        resp.set(38, format!("A{}", &amount[7..]).into_bytes()).unwrap();
    }
    let mut frame = Vec::new();
    FRAMING.encode(&pack(&resp, d).unwrap(), &mut frame).unwrap();
    frame
}

/// An mTLS ISO 8583 host: answers each request after `delay`, answers echoes only if `answer_echo`.
async fn host(ca: &Ca, delay: Duration, answer_echo: bool) -> (String, Arc<HostStats>) {
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
    let st = stats.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, stats) = (acceptor.clone(), st.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                stats.handshakes.fetch_add(1, Ordering::SeqCst);
                let id = {
                    let mut per = stats.requests_per_connection.lock().await;
                    per.push(0);
                    per.len() - 1
                };
                let (mut rd, mut wr) = tokio::io::split(tls);
                let outstanding = Arc::new(AtomicUsize::new(0));
                let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                let (out, st2) = (outstanding.clone(), stats.clone());
                tokio::spawn(async move {
                    let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
                    while let Ok(n @ 1..) = rd.read(&mut chunk).await {
                        buf.extend_from_slice(&chunk[..n]);
                        while let Some((frame, used)) = FRAMING.decode(&buf).unwrap() {
                            if out.fetch_add(1, Ordering::SeqCst) > 0 {
                                st2.overlaps.fetch_add(1, Ordering::SeqCst);
                            }
                            let _ = tx.send(frame.to_vec());
                            buf.drain(..used);
                        }
                    }
                });
                let d = Dictionary::from_json(DIALECT).unwrap();
                while let Some(frame) = rx.recv().await {
                    let req = unpack(&frame, &d).unwrap();
                    stats.requests_per_connection.lock().await[id] += 1;
                    let stan = req.get_str(11).unwrap().to_owned();
                    if !stats.in_flight_stans.lock().unwrap().insert(stan.clone()) {
                        stats.duplicate_stans.fetch_add(1, Ordering::SeqCst);
                    }
                    let is_echo = req.mti() == "0800";
                    if is_echo {
                        stats.echoes.fetch_add(1, Ordering::SeqCst);
                    } else {
                        tokio::time::sleep(delay).await;
                    }
                    let reply = respond(&req, &d);
                    stats.in_flight_stans.lock().unwrap().remove(&stan);
                    outstanding.fetch_sub(1, Ordering::SeqCst); // before writing: the client may send at once
                    if (answer_echo || !is_echo) && wr.write_all(&reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, stats)
}

fn iso() -> IsoHostConfig {
    IsoHostConfig::new(Dictionary::from_json(DIALECT).unwrap(), FRAMING)
}

fn purchase(amount: u64) -> Transaction {
    Transaction {
        transaction_id: format!("txn_{amount}"),
        kind: TransactionKind::Purchase,
        amount_minor: amount,
        currency: "INR".into(),
        merchant_id: "MERCHANT0000001".into(),
        terminal_id: "TERM0001".into(),
        card: Card { pan: "4111111111111111".into(), expiry: "2808".into() },
    }
}

const NO_ECHO: PoolConfig = PoolConfig { size: 8, echo_interval: Duration::from_secs(3_600), echo_timeout: Duration::from_secs(5) };

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_concurrent_transactions_across_the_pool() {
    let ca = ca();
    let (addr, stats) = host(&ca, Duration::from_millis(20), true).await;
    let pool = Arc::new(IsoHostPool::start(link_config(&addr, &ca), iso(), NO_ECHO).unwrap());
    assert_eq!(pool.wait_ready(Duration::from_secs(5)).await, 8, "pre-warmed");
    // TLS 1.3: the client counts a connection up slightly before the host finishes its side of the handshake.
    let deadline = Instant::now() + Duration::from_secs(2);
    while stats.handshakes.load(Ordering::SeqCst) < 8 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(stats.handshakes.load(Ordering::SeqCst), 8, "all connections open before any traffic");

    let mut tasks = JoinSet::new();
    for amount in 1..=50u64 {
        let pool = pool.clone();
        tasks.spawn(async move {
            let ctx = RequestContext::with_timeout(Duration::from_secs(10), format!("t{amount}"));
            (amount, pool.send_transaction(&ctx, &purchase(amount)).await)
        });
    }
    let mut done = 0;
    while let Some(joined) = tasks.join_next().await {
        let (amount, result) = joined.unwrap();
        match result.unwrap_or_else(|e| panic!("transaction {amount}: {e}")).decision {
            Decision::Approved { authorization_code } => assert_eq!(authorization_code, format!("A{amount:05}"),
                                                                    "response delivered to the wrong transaction"),
            other => panic!("transaction {amount}: {other:?}"),
        }
        done += 1;
    }
    assert_eq!(done, 50);
    assert_eq!(stats.overlaps.load(Ordering::SeqCst), 0, "a connection carried two requests at once");
    assert_eq!(stats.duplicate_stans.load(Ordering::SeqCst), 0, "two in-flight requests shared a STAN");
    let per = stats.requests_per_connection.lock().await;
    assert_eq!(per.iter().sum::<usize>(), 50);
    assert_eq!(per.iter().filter(|&&n| n > 0).count(), 8, "load spread over every connection: {per:?}");
}

#[tokio::test]
async fn idle_connections_echo_and_stay_open() {
    let ca = ca();
    let (addr, stats) = host(&ca, Duration::ZERO, true).await;
    let config = PoolConfig { size: 3, echo_interval: Duration::from_millis(100), echo_timeout: Duration::from_millis(500) };
    let pool = IsoHostPool::start(link_config(&addr, &ca), iso(), config).unwrap();
    assert_eq!(pool.wait_ready(Duration::from_secs(5)).await, 3);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(stats.echoes.load(Ordering::SeqCst) >= 6, "each idle connection echoes every interval");
    assert_eq!(stats.handshakes.load(Ordering::SeqCst), 3, "answered echoes never reset a connection");
    assert_eq!(pool.check_health().await.state, HostState::Up);
}

#[tokio::test]
async fn an_unanswered_echo_resets_the_connection() {
    let ca = ca();
    let (addr, stats) = host(&ca, Duration::ZERO, false).await;
    let config = PoolConfig { size: 2, echo_interval: Duration::from_millis(100), echo_timeout: Duration::from_millis(100) };
    let pool = IsoHostPool::start(link_config(&addr, &ca), iso(), config).unwrap();
    assert_eq!(pool.wait_ready(Duration::from_secs(5)).await, 2);
    let deadline = Instant::now() + Duration::from_secs(5);
    while stats.handshakes.load(Ordering::SeqCst) <= 2 {
        assert!(Instant::now() < deadline, "no reconnect after failed echoes");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_busy_pool_fails_cleanly_at_the_deadline_without_sending() {
    let ca = ca();
    let (addr, stats) = host(&ca, Duration::from_millis(400), true).await;
    let config = PoolConfig { size: 1, ..NO_ECHO };
    let pool = Arc::new(IsoHostPool::start(link_config(&addr, &ca), iso(), config).unwrap());
    assert_eq!(pool.wait_ready(Duration::from_secs(5)).await, 1);

    let first = {
        let pool = pool.clone();
        tokio::spawn(async move { pool.send_transaction(&RequestContext::with_timeout(Duration::from_secs(5), "a"), &purchase(1)).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await; // the only connection is now busy
    let second = pool.send_transaction(&RequestContext::with_timeout(Duration::from_millis(100), "b"), &purchase(2)).await;
    assert!(matches!(second, Err(HostError::Unavailable(_))), "{second:?}");
    assert!(first.await.unwrap().is_ok());
    assert_eq!(stats.requests_per_connection.lock().await.iter().sum::<usize>(), 1, "the second was never sent");
}

#[tokio::test]
async fn an_unreachable_host_reports_down() {
    let ca = ca();
    let pool = IsoHostPool::start(link_config("127.0.0.1:1", &ca), iso(), PoolConfig { size: 2, ..NO_ECHO }).unwrap();
    assert_eq!(pool.wait_ready(Duration::from_millis(300)).await, 0);
    assert_eq!(pool.check_health().await.state, HostState::Down);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echoes_never_share_a_connection_with_a_transaction() {
    let ca = ca();
    let (addr, stats) = host(&ca, Duration::from_millis(60), true).await;
    let config = PoolConfig { size: 2, echo_interval: Duration::from_millis(15), echo_timeout: Duration::from_secs(1) };
    let pool = Arc::new(IsoHostPool::start(link_config(&addr, &ca), iso(), config).unwrap());
    assert_eq!(pool.wait_ready(Duration::from_secs(5)).await, 2);
    let mut tasks = JoinSet::new();
    // Staggered, so connections keep switching between busy and idle while echoes fire.
    for amount in 1..=10u64 {
        let pool = pool.clone();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(35 * amount)).await;
            pool.send_transaction(&RequestContext::with_timeout(Duration::from_secs(10), "t"), &purchase(amount)).await
        });
    }
    while let Some(joined) = tasks.join_next().await {
        joined.unwrap().unwrap();
    }
    assert!(stats.echoes.load(Ordering::SeqCst) > 0, "echoes ran during the test");
    assert_eq!(stats.overlaps.load(Ordering::SeqCst), 0, "an echo was sent on a busy connection");
}
