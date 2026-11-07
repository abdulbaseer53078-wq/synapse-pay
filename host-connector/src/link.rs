//! A persistent mutual-TLS connection to one acquirer host (Task 4.2).
//!
//! [`Link::start`] spawns a supervisor that connects, keeps the connection open, and reconnects with capped
//! exponential backoff whenever it drops. Bytes the host sends arrive as [`LinkEvent::Data`]; [`Link::send`]
//! writes to the current connection or fails at once. Nothing is queued while the link is down: a message
//! sent late is a message whose outcome nobody can reason about.
//!
//! Only the acquirer's CA is trusted (never the system roots), only TLS 1.3 and 1.2 are offered, and our
//! client certificate is always presented. No payload bytes are ever logged or put in an error.
//!
//! shortcut: one connection, no pool and no ISO 8583 echo keep-alive; add a pool when the acquirer's spec
//! allows more than one connection, and echo (0800) once framing exists.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Where the host is and how to authenticate to it. Certificates and the key are PEM files from the acquirer.
#[derive(Clone)]
pub struct LinkConfig {
    /// `host:port`.
    pub addr: String,
    /// The name the host's certificate must carry (SNI and verification).
    pub server_name: String,
    /// The acquirer's CA certificate(s): the only roots trusted for the host's certificate.
    pub ca_cert: PathBuf,
    /// Our client certificate chain, issued by or registered with the acquirer.
    pub client_cert: PathBuf,
    /// The client certificate's private key.
    pub client_key: PathBuf,
    /// Limit for TCP connect plus TLS handshake together.
    pub connect_timeout: Duration,
    /// Limit for writing one message to the socket.
    pub write_timeout: Duration,
    /// Idle time before TCP keepalive probes start (and the interval between them).
    pub tcp_keepalive: Duration,
    /// First reconnect delay; doubles per failed attempt up to `max_backoff`, resets once connected.
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl LinkConfig {
    /// A config with the defaults from the Step 4 design: 2 s connect, 2 s write, 30 s keepalive,
    /// reconnect backoff from 250 ms to 30 s.
    pub fn new(addr: impl Into<String>, server_name: impl Into<String>, ca_cert: impl Into<PathBuf>,
               client_cert: impl Into<PathBuf>, client_key: impl Into<PathBuf>) -> Self {
        Self {
            addr: addr.into(),
            server_name: server_name.into(),
            ca_cert: ca_cert.into(),
            client_cert: client_cert.into(),
            client_key: client_key.into(),
            connect_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            tcp_keepalive: Duration::from_secs(30),
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// Paths are shown, but never key material.
impl fmt::Debug for LinkConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkConfig").field("addr", &self.addr).field("server_name", &self.server_name)
            .field("ca_cert", &self.ca_cert).field("client_cert", &self.client_cert)
            .field("connect_timeout", &self.connect_timeout).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkError {
    /// The certificates or key couldn't be loaded, or the server name is invalid. Retrying won't help.
    Config(String),
    /// TCP connect or I/O failed (refused, reset, unreachable).
    Io(String),
    /// TLS failed: untrusted host certificate, our certificate rejected, protocol mismatch.
    Tls(String),
    /// Connect plus handshake, or a write, took longer than its limit.
    Timeout,
    /// The host closed the connection.
    Closed,
    /// No connection right now; nothing was sent.
    NotConnected,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(why) => write!(f, "link configuration: {why}"),
            Self::Io(why) => write!(f, "connection: {why}"),
            Self::Tls(why) => write!(f, "TLS: {why}"),
            Self::Timeout => write!(f, "timed out"),
            Self::Closed => write!(f, "host closed the connection"),
            Self::NotConnected => write!(f, "not connected to the host"),
        }
    }
}

impl std::error::Error for LinkError {}

/// rustls reports TLS failures as io::Error wrapping a rustls::Error.
fn classify(e: io::Error) -> LinkError {
    match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(tls) => LinkError::Tls(tls.to_string()),
        None if e.kind() == io::ErrorKind::UnexpectedEof => LinkError::Closed,
        None => LinkError::Io(e.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkState {
    /// First connection attempt in progress.
    Connecting,
    Up { since: Instant },
    /// Waiting to retry after `error`.
    Down { error: LinkError, retry_in: Duration },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// A new connection is up. Any partially received message from an earlier connection is void.
    Connected,
    /// Bytes from the host, in order. TCP is a stream: one chunk may hold part of a message or several.
    Data(Vec<u8>),
    Disconnected(LinkError),
}

fn tls_connector(config: &LinkConfig) -> Result<TlsConnector, LinkError> {
    let bad = |what: &str, e: &dyn fmt::Display| LinkError::Config(format!("{what}: {e}"));
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&config.ca_cert).map_err(|e| bad("ca_cert", &e))? {
        roots.add(cert.map_err(|e| bad("ca_cert", &e))?).map_err(|e| bad("ca_cert", &e))?;
    }
    if roots.is_empty() {
        return Err(LinkError::Config("ca_cert: no certificates found".into()));
    }
    let chain = CertificateDer::pem_file_iter(&config.client_cert).map_err(|e| bad("client_cert", &e))?
        .collect::<Result<Vec<_>, _>>().map_err(|e| bad("client_cert", &e))?;
    // Never echo the key file's contents: report only that it couldn't be used.
    let key = PrivateKeyDer::from_pem_file(&config.client_key)
        .map_err(|_| LinkError::Config("client_key: not a readable PEM private key".into()))?;

    let tls = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| bad("tls", &e))?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|e| bad("client_cert/client_key", &e))?;
    Ok(TlsConnector::from(Arc::new(tls)))
}

/// One connection attempt: TCP connect and TLS handshake, both inside `connect_timeout`.
async fn connect(config: &LinkConfig, tls: &TlsConnector) -> Result<TlsStream<TcpStream>, LinkError> {
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|e| LinkError::Config(format!("server_name: {e}")))?;
    let attempt = async {
        let tcp = TcpStream::connect(&config.addr).await.map_err(classify)?;
        tcp.set_nodelay(true).map_err(classify)?; // small request/response messages: don't batch them
        let keepalive = TcpKeepalive::new().with_time(config.tcp_keepalive).with_interval(config.tcp_keepalive);
        SockRef::from(&tcp).set_tcp_keepalive(&keepalive).map_err(classify)?;
        tls.connect(server_name, tcp).await.map_err(classify)
    };
    tokio::time::timeout(config.connect_timeout, attempt).await.map_err(|_| LinkError::Timeout)?
}

/// The current connection's write half, and how to tell its supervisor that a write broke it. One Notify per
/// connection, so a failure on an old connection can never tear down a newer one.
type Writer = (WriteHalf<TlsStream<TcpStream>>, Arc<Notify>);

/// A supervised connection to one host. Dropping it closes the connection and stops reconnecting.
pub struct Link {
    writer: Arc<Mutex<Option<Writer>>>,
    // Shared with the supervisor. Whoever clears the writer publishes Down while holding the writer lock, and
    // Up is only published for a freshly installed writer, so Up never outlives the socket it describes.
    state_tx: Arc<watch::Sender<LinkState>>,
    state: watch::Receiver<LinkState>,
    write_timeout: Duration,
    supervisor: JoinHandle<()>,
}

impl Link {
    /// Validates the config, then connects in the background. Returns the link and its event stream, which
    /// the caller must keep reading (a full channel pauses reading from the host).
    pub fn start(config: LinkConfig) -> Result<(Self, mpsc::Receiver<LinkEvent>), LinkError> {
        let tls = tls_connector(&config)?;
        let (events_tx, events) = mpsc::channel(256);
        let (state_tx, state) = watch::channel(LinkState::Connecting);
        let state_tx = Arc::new(state_tx);
        let writer = Arc::new(Mutex::new(None));
        let supervisor = tokio::spawn(supervise(config.clone(), tls, writer.clone(), state_tx.clone(), events_tx));
        Ok((Self { writer, state_tx, state, write_timeout: config.write_timeout, supervisor }, events))
    }

    pub fn state(&self) -> LinkState {
        self.state.borrow().clone()
    }

    /// Waits until the link is up, or `timeout` passes. Returns whether it is up.
    pub async fn wait_up(&self, timeout: Duration) -> bool {
        let mut state = self.state.clone();
        tokio::time::timeout(timeout, state.wait_for(|s| matches!(s, LinkState::Up { .. })))
            .await.is_ok_and(|r| r.is_ok())
    }

    /// Writes `bytes` to the current connection. `NotConnected` means nothing was sent; any other error
    /// means some of it may have reached the host, and the connection is dropped and re-established.
    pub async fn send(&self, bytes: &[u8]) -> Result<(), LinkError> {
        let mut guard = self.writer.lock().await;
        let (writer, broken) = guard.as_mut().ok_or(LinkError::NotConnected)?;
        let write = async {
            writer.write_all(bytes).await?;
            writer.flush().await
        };
        let result = match tokio::time::timeout(self.write_timeout, write).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => classify(e),
            Err(_) => LinkError::Timeout,
        };
        broken.notify_one(); // the supervisor tears down the read side and reconnects
        *guard = None;
        self.state_tx.send_replace(LinkState::Down { error: result.clone(), retry_in: Duration::ZERO });
        Err(result)
    }
}

impl Link {
    /// Drops the current connection (e.g. after a failed echo); the supervisor opens a new one after its
    /// usual backoff. No-op while already down.
    pub async fn reconnect(&self) {
        let mut guard = self.writer.lock().await;
        if let Some((_, broken)) = guard.take() {
            broken.notify_one();
            let error = LinkError::Io("connection dropped to reconnect".into());
            self.state_tx.send_replace(LinkState::Down { error, retry_in: Duration::ZERO });
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.supervisor.abort();
    }
}

async fn supervise(config: LinkConfig, tls: TlsConnector, writer: Arc<Mutex<Option<Writer>>>,
                   state: Arc<watch::Sender<LinkState>>, events: mpsc::Sender<LinkEvent>) {
    let mut backoff = config.initial_backoff;
    loop {
        let error = match connect(&config, &tls).await {
            Ok(stream) => {
                backoff = config.initial_backoff;
                let (mut reader, write_half) = tokio::io::split(stream);
                let broken = Arc::new(Notify::new());
                *writer.lock().await = Some((write_half, broken.clone()));
                state.send_replace(LinkState::Up { since: Instant::now() });
                if events.send(LinkEvent::Connected).await.is_err() {
                    return; // nobody is listening: the link was dropped
                }
                let mut buf = vec![0u8; 16 * 1024];
                let error = loop {
                    tokio::select! {
                        read = reader.read(&mut buf) => match read {
                            Ok(0) => break LinkError::Closed,
                            Ok(n) => if events.send(LinkEvent::Data(buf[..n].to_vec())).await.is_err() { return },
                            Err(e) => break classify(e),
                        },
                        () = broken.notified() => break LinkError::Io("write failed or connection reset".into()),
                    }
                };
                // Down before anyone hears of the disconnect, so a caller failed by it never sees a stale Up.
                let mut guard = writer.lock().await;
                *guard = None;
                state.send_replace(LinkState::Down { error: error.clone(), retry_in: backoff });
                drop(guard);
                if events.send(LinkEvent::Disconnected(error.clone())).await.is_err() {
                    return;
                }
                error
            }
            Err(error) => error,
        };
        if matches!(error, LinkError::Config(_)) {
            state.send_replace(LinkState::Down { error, retry_in: Duration::MAX });
            return; // a bad server_name won't fix itself
        }
        state.send_replace(LinkState::Down { error, retry_in: backoff });
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(config.max_backoff);
    }
}
