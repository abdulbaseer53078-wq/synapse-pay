//! Task 4.2: a persistent mutual-TLS link, proven against a local mTLS host with its own throwaway CA.
//!
//! The acceptance test against the acquirer's real test host is `acquirer_test_host_stays_up_5_minutes`
//! (ignored; needs ACQUIRER_* env vars, see below).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use host_connector::link::{Link, LinkConfig, LinkError, LinkEvent, LinkState};
use rcgen::{BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{self, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

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

/// (cert PEM, key PEM) for `name`, issued by `ca`.
fn leaf(ca: &Ca, name: &str, usage: ExtendedKeyUsagePurpose) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    params.extended_key_usages = vec![usage];
    (params.signed_by(&key, &ca.cert, &ca.key).unwrap().pem(), key.serialize_pem())
}

fn temp_dir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!("link-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A client config trusting `trusted` for the host, presenting a certificate from `issuer`.
fn client_config(addr: &str, trusted: &Ca, issuer: &Ca) -> LinkConfig {
    let dir = temp_dir();
    let (cert, key) = leaf(issuer, "synapsepay-client", ExtendedKeyUsagePurpose::ClientAuth);
    std::fs::write(dir.join("ca.pem"), trusted.cert.pem()).unwrap();
    std::fs::write(dir.join("client.pem"), cert).unwrap();
    std::fs::write(dir.join("client-key.pem"), key).unwrap();
    let mut config = LinkConfig::new(addr, "localhost", dir.join("ca.pem"), dir.join("client.pem"),
                                     dir.join("client-key.pem"));
    config.connect_timeout = Duration::from_millis(500);
    config.initial_backoff = Duration::from_millis(50);
    config.max_backoff = Duration::from_millis(200);
    config
}

/// A local mTLS host: certificate for "localhost" from `ca`, requiring client certificates from `ca`.
/// Echoes what it receives; with `drop_first`, closes the first connection right after the handshake.
/// Returns its address and how many TLS handshakes succeeded.
async fn mtls_host(ca: &Ca, drop_first: bool) -> (String, Arc<AtomicUsize>) {
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
    let handshakes = Arc::new(AtomicUsize::new(0));
    let count = handshakes.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, count) = (acceptor.clone(), count.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                if count.fetch_add(1, Ordering::SeqCst) == 0 && drop_first {
                    return; // dropped without close_notify, like a host or firewall cutting the line
                }
                let mut buf = [0u8; 1024];
                while let Ok(n @ 1..) = tls.read(&mut buf).await {
                    if tls.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, handshakes)
}

async fn next_event(events: &mut mpsc::Receiver<LinkEvent>) -> LinkEvent {
    tokio::time::timeout(Duration::from_secs(5), events.recv()).await.expect("no link event within 5 s").unwrap()
}

async fn wait_down(link: &Link) -> LinkError {
    for _ in 0..100 {
        if let LinkState::Down { error, .. } = link.state() {
            return error;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("link never went down; state {:?}", link.state());
}

#[tokio::test(flavor = "multi_thread")]
async fn stays_connected_and_reuses_one_connection() {
    let ca = ca();
    let (addr, handshakes) = mtls_host(&ca, false).await;
    let (link, mut events) = Link::start(client_config(&addr, &ca, &ca)).unwrap();
    assert_eq!(next_event(&mut events).await, LinkEvent::Connected);

    let hold = std::env::var("LINK_HOLD_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    for _ in 0..3 {
        link.send(b"0800").await.unwrap();
        assert_eq!(next_event(&mut events).await, LinkEvent::Data(b"0800".to_vec()));
        tokio::time::sleep(Duration::from_secs(hold) / 3).await;
    }
    assert!(matches!(link.state(), LinkState::Up { .. }));
    assert_eq!(handshakes.load(Ordering::SeqCst), 1, "every send reused the one persistent connection");
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnects_after_the_host_drops_the_connection() {
    let ca = ca();
    let (addr, handshakes) = mtls_host(&ca, true).await;
    let (link, mut events) = Link::start(client_config(&addr, &ca, &ca)).unwrap();
    assert_eq!(next_event(&mut events).await, LinkEvent::Connected);
    assert!(matches!(next_event(&mut events).await, LinkEvent::Disconnected(_)));
    assert_eq!(next_event(&mut events).await, LinkEvent::Connected);
    link.send(b"after reconnect").await.unwrap();
    assert_eq!(next_event(&mut events).await, LinkEvent::Data(b"after reconnect".to_vec()));
    assert_eq!(handshakes.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn host_with_an_untrusted_certificate_is_refused() {
    let (host_ca, other_ca) = (ca(), ca());
    let (addr, _) = mtls_host(&host_ca, false).await;
    let (link, _events) = Link::start(client_config(&addr, &other_ca, &host_ca)).unwrap();
    assert!(matches!(wait_down(&link).await, LinkError::Tls(_)));
    assert!(matches!(link.send(b"x").await, Err(LinkError::NotConnected)));
}

#[tokio::test(flavor = "multi_thread")]
async fn host_refuses_a_client_certificate_it_did_not_issue() {
    let (host_ca, impostor_ca) = (ca(), ca());
    let (addr, handshakes) = mtls_host(&host_ca, false).await;
    let (_link, mut events) = Link::start(client_config(&addr, &host_ca, &impostor_ca)).unwrap();
    // With TLS 1.3 the client may finish its side before the host's rejection arrives, so check the host.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(handshakes.load(Ordering::SeqCst), 0, "host must not accept an unknown client certificate");
    while let Ok(event) = events.try_recv() {
        assert!(!matches!(event, LinkEvent::Data(_)));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_hangs_mid_handshake_times_out() {
    // Accepts TCP (the OS backlog completes it) but never answers the TLS ClientHello.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ca = ca();
    let started = std::time::Instant::now();
    let (link, _events) = Link::start(client_config(&silent.local_addr().unwrap().to_string(), &ca, &ca)).unwrap();
    assert_eq!(wait_down(&link).await, LinkError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2), "connect_timeout is 500 ms");
}

#[tokio::test(flavor = "multi_thread")]
async fn send_fails_fast_when_the_host_is_down() {
    let addr = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string(); // closed now
    let ca = ca();
    let (link, _events) = Link::start(client_config(&addr, &ca, &ca)).unwrap();
    assert_eq!(link.send(b"0100").await, Err(LinkError::NotConnected));
    // Refused on Linux; Windows retries the SYN for ~2 s, so the 500 ms connect timeout fires first.
    assert!(matches!(wait_down(&link).await, LinkError::Io(_) | LinkError::Timeout));
}

#[tokio::test(flavor = "multi_thread")]
async fn unusable_credentials_fail_at_start_without_revealing_the_key() {
    let ca = ca();
    let mut config = client_config("127.0.0.1:1", &ca, &ca);
    std::fs::write(&config.client_key, "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n").unwrap();
    let Err(LinkError::Config(why)) = Link::start(config.clone()) else { panic!("expected a config error") };
    assert!(!why.contains("c2VjcmV0"), "{why}");
    config.ca_cert = PathBuf::from("does-not-exist.pem");
    assert!(matches!(Link::start(config), Err(LinkError::Config(_))));
}

/// Acceptance: connect to the acquirer's test host and stay up for 5 minutes. Run with
/// `cargo test --test link -- --ignored` and ACQUIRER_ADDR (host:port), ACQUIRER_SERVER_NAME,
/// ACQUIRER_CA, CLIENT_CERT, CLIENT_KEY (PEM file paths) set.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the acquirer's test host and our client certificate"]
async fn acquirer_test_host_stays_up_5_minutes() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set"));
    let config = LinkConfig::new(env("ACQUIRER_ADDR"), env("ACQUIRER_SERVER_NAME"), env("ACQUIRER_CA"),
                                 env("CLIENT_CERT"), env("CLIENT_KEY"));
    let (link, mut events) = Link::start(config).unwrap();
    assert!(link.wait_up(Duration::from_secs(10)).await, "not up: {:?}", link.state());
    let held = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if let Some(LinkEvent::Disconnected(why)) = events.recv().await {
                return why;
            }
        }
    }).await;
    if let Ok(why) = held {
        panic!("connection dropped before 5 minutes: {why}");
    }
    assert!(matches!(link.state(), LinkState::Up { .. }));
}
