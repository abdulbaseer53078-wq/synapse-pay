//! Host Connector interface (Stage 1, Step 4): how the platform talks to an acquirer's processing host.
//!
//! Core logic depends only on [`HostConnector`]; each acquirer (ISO 8583 over TCP, or anything else) is an
//! implementation chosen by configuration, so adding a second acquirer means adding an implementation,
//! not changing callers. Implementations are object-safe, so a router can hold `Vec<Box<dyn HostConnector>>`.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

pub mod audit;
pub mod framing;
pub mod iso_host;
pub mod link;
pub mod mock;
pub mod pool;
pub mod stan;
pub mod unified;

/// A boxed future, so the trait stays usable as `dyn HostConnector` without an async-trait dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait HostConnector: Send + Sync {
    /// Sends one transaction and waits for the host's answer, giving up at `ctx.deadline`.
    /// A decline is an `Ok` answer; `Err` means the exchange itself failed (see [`HostError`]).
    fn send_transaction<'a>(&'a self, ctx: &'a RequestContext, txn: &'a Transaction)
        -> BoxFuture<'a, Result<HostResponse, HostError>>;

    /// Whether the host can take traffic right now. Never fails: an unreachable host is `HostState::Down`.
    fn check_health(&self) -> BoxFuture<'_, HostStatus>;
}

/// Per-request context (Go's `context.Context`): when to give up, how to correlate logs, and which hosts this
/// particular request may use. The hint is per request because the routing engine decides it per transaction.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub deadline: Instant,
    pub trace_id: String,
    /// Hosts to try, in order. Empty means "whatever the connector is configured with".
    pub host_hint: Vec<String>,
}

impl RequestContext {
    pub fn with_timeout(timeout: Duration, trace_id: impl Into<String>) -> Self {
        Self { deadline: Instant::now() + timeout, trace_id: trace_id.into(), host_hint: Vec::new() }
    }

    /// Choose the hosts this request may use, in preference order.
    pub fn with_hosts(mut self, hosts: Vec<String>) -> Self {
        self.host_hint = hosts;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionKind {
    /// Authorize only (ISO 8583 0100); captured later.
    Authorization,
    /// Authorize and capture in one step (0200).
    Purchase,
    /// Undo an earlier transaction (0400), e.g. after a timeout left its outcome unknown.
    Reversal { original_transaction_id: String },
}

/// What the platform asks the host to do, independent of any wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The platform's transaction_id; implementations derive host references (STAN, RRN) from it.
    pub transaction_id: String,
    pub kind: TransactionKind,
    /// Smallest currency unit, as in the API contract (paise for INR).
    pub amount_minor: u64,
    /// ISO 4217 alphabetic code, e.g. "INR". Implementations map it to the numeric code their host wants.
    pub currency: String,
    pub merchant_id: String,
    pub terminal_id: String,
    pub card: Card,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Card {
    pub pan: String,
    /// YYMM.
    pub expiry: String,
}

/// Shows only the last 4 digits: transactions get logged, card numbers must not be.
impl fmt::Debug for Card {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let last4 = self.pan.get(self.pan.len().saturating_sub(4)..).unwrap_or("");
        f.debug_struct("Card").field("pan", &format_args!("****{last4}")).field("expiry", &"**").finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResponse {
    pub decision: Decision,
    /// The host's raw response code (ISO 8583 DE 39), kept for receipts, disputes and reconciliation.
    pub response_code: String,
    /// The host's reference for this transaction (e.g. the RRN, DE 37), if it gave one.
    pub host_reference: Option<String>,
    /// Which host actually answered. Filled by the failover layer, empty when a single connector answered
    /// directly. The audit trail must record this, not the host we asked for: they differ when a retry happened.
    pub host_used: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Approved { authorization_code: String },
    Declined { category: DeclineCategory },
}

/// Matches the API contract's error_category: the Cascade Engine retries a soft decline on another
/// acquirer and stops on a hard one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclineCategory {
    Soft,
    Hard,
}

/// The exchange failed. The variants differ in the one thing callers must know: did the host get it?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// Definitely not delivered (no connection, host down, rejected before sending). Safe to retry or
    /// send to another acquirer.
    Unavailable(String),
    /// Sent, but no answer by the deadline: the host may have approved it. Never retry blindly; reverse it.
    Timeout,
    /// The connection failed after (part of) the request was written: the host may have acted on it.
    ConnectionLost(String),
    /// The host answered with something unusable (unparseable, or not a reply to this request). Treat the
    /// outcome as unknown, like a timeout.
    Protocol(String),
}

impl HostError {
    /// Whether the host might have acted on the request, so it needs a reversal rather than a retry.
    pub fn outcome_unknown(&self) -> bool {
        !matches!(self, Self::Unavailable(_))
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(why) => write!(f, "host unavailable: {why}"),
            Self::Timeout => write!(f, "host did not answer before the deadline"),
            Self::ConnectionLost(why) => write!(f, "connection lost after sending: {why}"),
            Self::Protocol(why) => write!(f, "unusable host response: {why}"),
        }
    }
}

impl std::error::Error for HostError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStatus {
    pub state: HostState,
    /// Round-trip time of the health check, if the host answered.
    pub latency: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Up,
    /// Answering, but slowly or with errors: route around it if another host is Up.
    Degraded,
    Down,
}
