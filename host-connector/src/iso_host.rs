//! ISO 8583 host connector (Task 4.4): [`Transaction`] → data elements → `pack` → length-prefix frame →
//! mTLS [`Link`] → wait for the matching response → frame → `unpack` → [`HostResponse`].
//!
//! Requests and responses are matched by STAN (DE 11): one connection carries many transactions at once and
//! hosts answer in any order. Each request gets a fresh 6-digit STAN; transaction_id can't fit DE 11.
//!
//! [`IsoHostConnector::echo`] sends the 0800 network echo; the pool ([`crate::pool`]) runs it on idle connections.
//!
//! Every message sent and received, including late responses nobody waits for any more, is written to the
//! config's [`AuditSink`] as a redacted [`crate::audit`] record. If the outbound record can't be written, the
//! message isn't sent. A response that misses its deadline kills the connection: after a cut cable or a
//! hung host the socket can't be trusted, and a late reply must never be taken for a newer request's.
//!
//! Reversals (0400) quote the original request in DE 90 (original MTI, STAN and DE 7). The connector remembers
//! the most recent originals it sent (see [`Originals`]), shared by all of a host's connections.
//!
//! shortcut: originals live in memory only; a restart between a timeout and its reversal loses them. Persist
//! them (or the reversal queue) when reversals move to a background job.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use iso8583::{pack, unpack, Dictionary, Iso8583Message};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::audit::{redact, AuditSink, Direction};
use crate::framing::Framing;
use crate::link::{Link, LinkError, LinkEvent, LinkState};
use crate::{BoxFuture, Decision, DeclineCategory, HostConnector, HostError, HostResponse, HostState, HostStatus,
            RequestContext, Transaction, TransactionKind};

/// One acquirer's ISO 8583 settings.
#[derive(Clone)]
pub struct IsoHostConfig {
    pub dictionary: Dictionary,
    pub framing: Framing,
    /// DE 39 codes worth retrying on another acquirer (Cascade Engine). Any other non-approval is hard.
    pub soft_decline_codes: Vec<String>,
    /// DE 22 POS entry mode, until terminals report it per transaction.
    pub pos_entry_mode: String,
    /// Where redacted records of every message go (RBI retention). None only in tests: production must set it.
    pub audit: Option<Arc<dyn AuditSink>>,
}

impl IsoHostConfig {
    /// Soft by default: 19 re-enter, 68 response late, 91 issuer unavailable, 96 system malfunction.
    pub fn new(dictionary: Dictionary, framing: Framing) -> Self {
        Self {
            dictionary,
            framing,
            soft_decline_codes: ["19", "68", "91", "96"].map(String::from).to_vec(),
            pos_entry_mode: "051".into(), // chip
            audit: None,
        }
    }
}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Vec<u8>>>>>;

/// What a reversal needs to quote about the request it undoes (DE 90).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Original {
    mti: String,
    stan: String,
    transmitted: String, // DE 7, MMDDhhmmss
}

/// The most recent requests sent to one host, by transaction_id, so a reversal can find its original.
#[derive(Default)]
pub struct OriginalsInner {
    by_id: HashMap<String, Original>,
    order: VecDeque<String>,
}

/// Shared by every connection to one host (a reversal may leave on a different connection than its original).
pub type Originals = Arc<Mutex<OriginalsInner>>;

/// How many originals to remember. Reversals follow within seconds, so this only needs to cover a burst.
const ORIGINALS_KEPT: usize = 10_000;

impl OriginalsInner {
    fn remember(&mut self, transaction_id: &str, original: Original) {
        if self.by_id.insert(transaction_id.to_owned(), original).is_none() {
            self.order.push_back(transaction_id.to_owned());
        }
        while self.order.len() > ORIGINALS_KEPT {
            if let Some(old) = self.order.pop_front() {
                self.by_id.remove(&old);
            }
        }
    }

    fn get(&self, transaction_id: &str) -> Option<Original> {
        self.by_id.get(transaction_id).cloned()
    }
}

/// Removes a request's waiter however `send_transaction` ends, including when its future is dropped.
struct Waiting<'a> {
    pending: &'a Pending,
    stan: String,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.pending.lock().unwrap().remove(&self.stan);
    }
}

pub struct IsoHostConnector {
    link: Link,
    config: Arc<IsoHostConfig>,
    pending: Pending,
    stan: Arc<AtomicU32>,
    originals: Originals,
    reader: JoinHandle<()>,
}

impl IsoHostConnector {
    /// Takes over the link's event stream. Must be called inside a Tokio runtime.
    pub fn new(link: Link, events: mpsc::Receiver<LinkEvent>, config: impl Into<Arc<IsoHostConfig>>) -> Self {
        Self::with_stans(link, events, config.into(), Arc::default(), Originals::default())
    }

    /// Like `new`, drawing STANs from a counter shared with the host's other connections, so no two
    /// in-flight requests to one host ever carry the same STAN.
    pub(crate) fn with_stans(link: Link, events: mpsc::Receiver<LinkEvent>, config: Arc<IsoHostConfig>,
                             stan: Arc<AtomicU32>, originals: Originals) -> Self {
        let pending = Pending::default();
        let reader = tokio::spawn(read_responses(events, config.clone(), pending.clone()));
        Self { link, config, pending, stan, originals, reader }
    }

    pub fn link(&self) -> &Link {
        &self.link
    }

    fn next_stan(&self) -> String {
        format!("{:06}", self.stan.fetch_add(1, Ordering::Relaxed) % 999_999 + 1)
    }

    /// Sends one framed request and returns the raw response with the same STAN, auditing both.
    async fn exchange(&self, ctx: &RequestContext, transaction_id: &str, stan: String, wire: &[u8])
        -> Result<Vec<u8>, HostError> {
        if let Some(sink) = &self.config.audit {
            sink.record(&redact(wire, &self.config.dictionary, transaction_id, Direction::Outbound))
                .map_err(|e| HostError::Unavailable(format!("audit record not written, so not sent: {e}")))?;
        }
        let mut frame = Vec::with_capacity(wire.len() + 4);
        self.config.framing.encode(wire, &mut frame).map_err(|e| HostError::Unavailable(e.to_string()))?;

        // Register before sending, so even an instant reply finds its waiter.
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(stan.clone(), tx);
        let _waiting = Waiting { pending: &self.pending, stan };

        match self.link.send(&frame).await {
            Ok(()) => {}
            Err(LinkError::NotConnected) => return Err(HostError::Unavailable("not connected to the host".into())),
            Err(e) => return Err(HostError::ConnectionLost(e.to_string())),
        }
        let raw = match tokio::time::timeout_at(tokio::time::Instant::from_std(ctx.deadline), rx).await {
            Err(_) => {
                self.link.reconnect().await;
                return Err(HostError::Timeout);
            }
            Ok(Err(_)) => return Err(HostError::ConnectionLost("connection dropped before the response".into())),
            Ok(Ok(raw)) => raw,
        };
        if let Some(sink) = &self.config.audit {
            // The answer is already here: failing now would turn a known outcome into an unknown one.
            if let Err(e) = sink.record(&redact(&raw, &self.config.dictionary, transaction_id, Direction::Inbound)) {
                // shortcut: stderr until the service has metrics; alert on this line.
                eprintln!("AUDIT FAILURE: inbound record for {transaction_id} not written: {e}");
            }
        }
        Ok(raw)
    }

    /// ISO 8583 network echo: an 0800 (DE 70 = 301) that must come back as an 0810 with DE 39 "00".
    pub async fn echo(&self, ctx: &RequestContext) -> Result<(), HostError> {
        let stan = self.next_stan();
        let wire = build_echo(&stan, SystemTime::now(), &self.config).map_err(HostError::Unavailable)?;
        let raw = self.exchange(ctx, "network-echo", stan, &wire).await?;
        let msg = unpack(&raw, &self.config.dictionary).map_err(|e| HostError::Protocol(e.to_string()))?;
        match (msg.mti(), msg.get_str(39)) {
            ("0810", Some("00")) => Ok(()),
            (mti, code) => Err(HostError::Protocol(format!("echo answered with {mti}, DE 39 {code:?}"))),
        }
    }
}

impl Drop for IsoHostConnector {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl IsoHostConnector {
    /// Send with a STAN chosen by the caller; the trait method mints its own.
    ///
    /// DE 11 is what ties a request to its response and to any reversal built from it, so a cross-host retry
    /// must reuse one STAN. Two STANs for one payment are two transactions on the wire, and the clearing file can
    /// only reconcile one of them.
    pub fn send_with_stan<'a>(&'a self, ctx: &'a RequestContext, txn: &'a Transaction, stan: String)
        -> BoxFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async move {
            if Instant::now() >= ctx.deadline {
                return Err(HostError::Unavailable("deadline passed before sending".into()));
            }
            let original = match &txn.kind {
                TransactionKind::Reversal { original_transaction_id } => Some(
                    self.originals.lock().unwrap().get(original_transaction_id).ok_or_else(|| {
                        HostError::Unavailable("no record of the original request to reverse".into())
                    })?,
                ),
                _ => None,
            };
            let (mti, transmitted, wire) =
                build_request(txn, &stan, SystemTime::now(), &self.config, original.as_ref())
                    .map_err(HostError::Unavailable)?;
            if original.is_none() {
                // Remembered before sending: the reversal for a timeout must find it.
                self.originals.lock().unwrap().remember(
                    &txn.transaction_id,
                    Original { mti: mti.clone(), stan: stan.clone(), transmitted },
                );
            }
            let raw = self.exchange(ctx, &txn.transaction_id, stan, &wire).await?;
            parse_response(&raw, &mti, &self.config)
        })
    }
}

impl HostConnector for IsoHostConnector {
    fn send_transaction<'a>(&'a self, ctx: &'a RequestContext, txn: &'a Transaction)
        -> BoxFuture<'a, Result<HostResponse, HostError>> {
        self.send_with_stan(ctx, txn, self.next_stan())
    }

    fn check_health(&self) -> BoxFuture<'_, HostStatus> {
        Box::pin(async move {
            let state = match self.link.state() {
                LinkState::Up { .. } => HostState::Up,
                _ => HostState::Down,
            };
            HostStatus { state, latency: None }
        })
    }
}

/// Reads the link's byte stream, cuts it into frames and hands each response to the request with its STAN.
async fn read_responses(mut events: mpsc::Receiver<LinkEvent>, config: Arc<IsoHostConfig>, pending: Pending) {
    let mut buf = Vec::new();
    while let Some(event) = events.recv().await {
        match event {
            LinkEvent::Connected => buf.clear(),
            // Waiters' senders are dropped: they report ConnectionLost (outcome unknown).
            LinkEvent::Disconnected(_) => {
                buf.clear();
                pending.lock().unwrap().clear();
            }
            LinkEvent::Data(chunk) => {
                buf.extend_from_slice(&chunk);
                loop {
                    match config.framing.decode(&buf) {
                        Ok(Some((frame, used))) => {
                            deliver(frame.to_vec(), &config, &pending);
                            buf.drain(..used);
                        }
                        Ok(None) => break,
                        // shortcut: a bad length header means the stream is out of sync; we drop what's buffered
                        // and fail the waiters, but don't force a reconnect (Link has no API for it yet).
                        Err(_) => {
                            buf.clear();
                            pending.lock().unwrap().clear();
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn deliver(frame: Vec<u8>, config: &IsoHostConfig, pending: &Pending) {
    let Ok(msg) = unpack(&frame, &config.dictionary) else { return }; // unreadable: its waiter times out
    let Some(stan) = msg.get_str(11).map(str::to_owned) else { return };
    drop(msg);
    let waiter = pending.lock().unwrap().remove(&stan);
    match waiter {
        Some(waiter) => {
            let _ = waiter.send(frame);
        }
        // No waiter: the request already timed out, so this may be a late approval the reversal must cover.
        // Audit it, since reconciliation needs it, under its STAN (the transaction_id isn't known here).
        None => if let Some(sink) = &config.audit {
            let id = format!("unmatched-stan-{stan}");
            if let Err(e) = sink.record(&redact(&frame, &config.dictionary, &id, Direction::Inbound)) {
                eprintln!("AUDIT FAILURE: inbound record for {id} not written: {e}");
            }
        },
    }
}

/// Maps a transaction onto the dialect's data elements and packs it. Fields the dialect doesn't define are
/// skipped; the dialect's `required` rules still apply. Errors never include field values.
/// Returns the MTI, the DE 7 sent, and the packed message. `original` is required for a reversal.
fn build_request(txn: &Transaction, stan: &str, now: SystemTime, config: &IsoHostConfig,
                 original: Option<&Original>) -> Result<(String, String, Vec<u8>), String> {
    let mti = match txn.kind {
        TransactionKind::Authorization => "0100",
        TransactionKind::Purchase => "0200",
        TransactionKind::Reversal { .. } => "0400",
    };
    let currency = numeric_currency(&txn.currency).ok_or_else(|| format!("unsupported currency {}", txn.currency))?;
    let amount = format!("{:012}", txn.amount_minor);
    if amount.len() > 12 {
        return Err("amount doesn't fit DE 4".into());
    }
    let t = Utc::from(now);
    let transmitted = format!("{:02}{:02}{:02}{:02}{:02}", t.month, t.day, t.hour, t.minute, t.second);
    // DE 90: original MTI, STAN and DE 7, then acquiring and forwarding institution IDs (zero: not assigned).
    let original_data = match (&txn.kind, original) {
        (TransactionKind::Reversal { .. }, Some(o)) => Some(format!("{}{}{}{:011}{:011}", o.mti, o.stan, o.transmitted, 0, 0)),
        (TransactionKind::Reversal { .. }, None) => return Err("a reversal needs its original request".into()),
        _ => None,
    };
    let fields = [
        (2, txn.card.pan.clone()),
        (3, "000000".into()), // purchase of goods and services
        (4, amount),
        (7, transmitted.clone()),
        (11, stan.into()),
        (12, format!("{:02}{:02}{:02}", t.hour, t.minute, t.second)), // shortcut: UTC as local time
        (13, format!("{:02}{:02}", t.month, t.day)),
        (14, txn.card.expiry.clone()),
        (22, config.pos_entry_mode.clone()),
        (25, "00".into()),
        (37, format!("{}{:03}{:02}{stan}", t.year % 10, t.day_of_year, t.hour)), // RRN: YDDDHH + STAN
        (41, txn.terminal_id.clone()),
        (42, txn.merchant_id.clone()),
        (49, currency.into()),
    ];
    let mut msg = Iso8583Message::new(mti).expect("fixed MTI");
    for (field, value) in fields.into_iter().chain(original_data.map(|v| (90, v))) {
        if config.dictionary.spec(field).is_some() {
            msg.set(field, value.into_bytes()).map_err(|e| e.to_string())?;
        }
    }
    let wire = pack(&msg, &config.dictionary).map_err(|e| format!("can't build {mti}: {e}"))?;
    Ok((mti.into(), transmitted, wire))
}

fn build_echo(stan: &str, now: SystemTime, config: &IsoHostConfig) -> Result<Vec<u8>, String> {
    let t = Utc::from(now);
    let mut msg = Iso8583Message::new("0800").expect("fixed MTI");
    let transmitted = format!("{:02}{:02}{:02}{:02}{:02}", t.month, t.day, t.hour, t.minute, t.second);
    for (field, value) in [(7, transmitted), (11, stan.to_owned()), (70, "301".to_owned())] {
        if config.dictionary.spec(field).is_some() {
            msg.set(field, value.into_bytes()).map_err(|e| e.to_string())?;
        }
    }
    pack(&msg, &config.dictionary).map_err(|e| format!("can't build 0800: {e}"))
}

fn parse_response(raw: &[u8], request_mti: &str, config: &IsoHostConfig) -> Result<HostResponse, HostError> {
    let msg = unpack(raw, &config.dictionary).map_err(|e| HostError::Protocol(e.to_string()))?;
    let expected = format!("{:04}", request_mti.parse::<u16>().expect("4-digit MTI") + 10);
    if msg.mti() != expected {
        return Err(HostError::Protocol(format!("expected a {expected} response, got {}", msg.mti())));
    }
    let code = msg.get_str(39).ok_or_else(|| HostError::Protocol("response has no DE 39".into()))?;
    let decision = if code == "00" {
        Decision::Approved { authorization_code: msg.get_str(38).unwrap_or_default().to_owned() }
    } else if config.soft_decline_codes.iter().any(|c| c == code) {
        Decision::Declined { category: DeclineCategory::Soft }
    } else {
        Decision::Declined { category: DeclineCategory::Hard }
    };
    Ok(HostResponse {
        decision,
        response_code: code.to_owned(),
        host_reference: msg.get_str(37).map(str::to_owned),
    })
}

/// ISO 4217 numeric codes for the currencies we settle in.
/// shortcut: a short static table; load the full ISO 4217 list when more currencies are onboarded.
fn numeric_currency(alpha: &str) -> Option<&'static str> {
    Some(match alpha {
        "INR" => "356",
        "USD" => "840",
        "EUR" => "978",
        "GBP" => "826",
        "AED" => "784",
        "SGD" => "702",
        _ => return None,
    })
}

/// A UTC calendar time, enough for the date fields, without a date library.
#[derive(Debug, PartialEq, Eq)]
struct Utc {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    day_of_year: u32,
}

impl From<SystemTime> for Utc {
    fn from(t: SystemTime) -> Self {
        let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
        // Howard Hinnant's civil_from_days.
        let z = days + 719_468;
        let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = yoe + era * 400 + i64::from(month <= 2);
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        const BEFORE: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        let day_of_year = BEFORE[month as usize - 1] + day + u32::from(leap && month > 2);
        let rem = rem as u32;
        Self { year, month, day, hour: rem / 3_600, minute: rem / 60 % 60, second: rem % 60, day_of_year }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn at(secs: u64) -> Utc {
        Utc::from(UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[test]
    fn utc_calendar_matches_known_dates() {
        let u = |year, month, day, hour, minute, second, day_of_year| Utc { year, month, day, hour, minute, second, day_of_year };
        assert_eq!(at(0), u(1970, 1, 1, 0, 0, 0, 1));
        assert_eq!(at(951_782_400), u(2000, 2, 29, 0, 0, 0, 60)); // leap century
        assert_eq!(at(1_709_164_800 + 37_230), u(2024, 2, 29, 10, 20, 30, 60));
        assert_eq!(at(1_703_980_800), u(2023, 12, 31, 0, 0, 0, 365));
        assert_eq!(at(1_735_603_200), u(2024, 12, 31, 0, 0, 0, 366));
    }
}
