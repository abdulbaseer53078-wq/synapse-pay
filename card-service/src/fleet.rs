//! Multi-host failover (Stage 3, Step 14.7).
//!
//! An [`IsoHostPool`] owns the sockets to *one* acquirer; this owns one pool per acquirer and decides which of
//! them a transaction is allowed to use. It is the composite the rest of the service sees: `Fleet` is a
//! `HostConnector`, so `CardFlow` and the HTTP handlers do not know whether there is one host behind them or five.
//!
//! Two rules matter here:
//!
//! * **One STAN per transaction.** DE 11 is what ties a request to its response and to any reversal built from
//!   it. Minting a second STAN for a retry would put two transactions on the wire for one customer payment, and
//!   the clearing file can only reconcile one of them. The STAN is minted once, above the loop.
//! * **Move on only when the request was never sent.** A host that is down or refuses the request
//!   (`Unavailable`) has done nothing, so the next host is tried. A host that times out or drops the connection
//!   may have approved the payment: asking a second host could charge the card twice, so the fleet stops and
//!   returns the unknown outcome for the caller to resolve (Step 19). A decline is an answer, never a reason to
//!   move on.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use host_connector::iso_host::Original;
use host_connector::pool::IsoHostPool;
use host_connector::stan::StanSource;
use host_connector::{BoxFuture, HostConnector, HostError, HostResponse, HostState, HostStatus, RequestContext,
                     Transaction};

/// Where the fleet's events go: one JSON object per call (stdout by default; tests capture them).
pub type EventSink = Arc<dyn Fn(serde_json::Value) + Send + Sync>;

pub struct Fleet {
    pub pools: HashMap<String, Arc<IsoHostPool>>,
    stans: Arc<StanSource>,
    events: EventSink,
}

impl Fleet {
    /// `stans` must be the source the pools were started with (`IsoHostPool::start_with_stans`): then a
    /// transaction's STAN can't collide with a pool's echo, and slots keep other card-service instances apart.
    pub fn new(pools: HashMap<String, Arc<IsoHostPool>>, stans: Arc<StanSource>) -> Self {
        Self { pools, stans, events: Arc::new(|event| println!("{event}")) }
    }

    pub fn with_event_sink(mut self, events: EventSink) -> Self {
        self.events = events;
        self
    }

    fn mint_stan(&self) -> String {
        self.stans.next()
    }

    /// The host that holds `transaction_id`'s original, and what a reversal must quote. At most one does: the
    /// fleet moves on only when a request was never sent, so only the host it reached remembers it.
    pub fn original(&self, transaction_id: &str) -> Option<(String, Original)> {
        self.pools.iter().find_map(|(host, pool)| pool.original(transaction_id).map(|o| (host.clone(), o)))
    }

    /// Puts a saved original back on its host after a restart. False if this fleet has no such host.
    pub fn restore_original(&self, host: &str, transaction_id: &str, original: Original) -> bool {
        self.pools.get(host).map(|pool| pool.restore_original(transaction_id, original)).is_some()
    }
}

/// HostError in the shared failover-event vocabulary.
fn failure_reason(error: &HostError) -> &'static str {
    match error {
        HostError::Timeout => "TIMEOUT",
        HostError::ConnectionLost(_) => "CONNECTION_LOST",
        HostError::Protocol(_) => "PROTOCOL_ERROR",
        HostError::Unavailable(_) => "UNAVAILABLE",
    }
}

impl HostConnector for Fleet {
    fn send_transaction<'a>(&'a self, ctx: &'a RequestContext, txn: &'a Transaction)
        -> BoxFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async move {
            let stan = self.mint_stan();
            let hint: Vec<String> = if ctx.host_hint.is_empty() {
                // No hint: the caller has one host in mind (or is a test). Try them all rather than fail.
                self.pools.keys().cloned().collect()
            } else {
                ctx.host_hint.clone()
            };

            // Only hosts that exist and have a live socket: a host with no socket is skipped, not waited on.
            // Ordered as the caller asked, so the routing engine's preference order survives.
            let candidates: Vec<(&String, &Arc<IsoHostPool>)> = hint.iter()
                .filter_map(|host_id| self.pools.get(host_id).map(|pool| (host_id, pool)))
                .filter(|(_, pool)| pool.connections_up() > 0)
                .collect();
            if candidates.is_empty() {
                return Err(HostError::Unavailable("no host in the hint is up".into()));
            }
            // The caller's first choice is down, so the payment starts on a backup: that is a failover too.
            if let (Some(first), Some((to, _))) = (ctx.host_hint.first(), candidates.first()) {
                if first != *to {
                    (self.events)(serde_json::json!({
                        "event": "FAILOVER_TRIGGERED", "layer": "HOST", "trace_id": ctx.trace_id,
                        "from_path": first, "to_path": to, "reason": "UNAVAILABLE", "latency_lost_ms": 0,
                    }));
                }
            }

            // Each host gets whatever is left of the caller's one deadline. It isn't split: a timeout ends the
            // attempt, so a slice would only turn answers into unknown outcomes. Only "never sent" moves on, and fast.
            // The host that just failed, why, and how long it took: reported once we know where the payment went.
            let mut failed: Option<(String, &'static str, u128)> = None;
            for (host_id, pool) in candidates {
                let remaining = ctx.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                if let Some((from, reason, lost_ms)) = failed.take() {
                    (self.events)(serde_json::json!({
                        "event": "FAILOVER_TRIGGERED", "layer": "HOST", "trace_id": ctx.trace_id,
                        "from_path": from, "to_path": host_id, "reason": reason, "latency_lost_ms": lost_ms,
                    }));
                }
                let started = Instant::now();
                let sent = pool.send_with_stan(ctx, txn, stan.clone()).await;
                if let Err(error) = &sent {
                    let reason = failure_reason(error);
                    let lost_ms = started.elapsed().as_millis();
                    // The STAN joins this to the redacted ISO 8583 audit records and the acquirer's own logs.
                    (self.events)(serde_json::json!({
                        "event": "HOST_ATTEMPT_FAILED", "trace_id": ctx.trace_id, "host": host_id,
                        "stan": stan, "reason": reason, "latency_ms": lost_ms,
                    }));
                    failed = Some((host_id.clone(), reason, lost_ms));
                }
                match sent {
                    Ok(mut response) => {
                        // The truth for the audit trail: not the host we asked for, the host that answered.
                        response.host_used = host_id.clone();
                        return Ok(response);
                    }
                    // The host may have acted: stop here rather than risk a second charge elsewhere.
                    Err(error) if error.outcome_unknown() => return Err(error),
                    Err(_) => {} // never sent: the next host is safe to ask
                }
            }
            Err(HostError::Unavailable("no host in the hint accepted the transaction before the deadline".into()))
        })
    }

    fn check_health(&self) -> BoxFuture<'_, HostStatus> {
        Box::pin(async move {
            let (mut up, mut total) = (0usize, 0usize);
            for pool in self.pools.values() {
                if pool.check_health().await.state == HostState::Up {
                    up += 1;
                }
                total += 1;
            }
            let state = if total == 0 || up == 0 {
                HostState::Down
            } else if up == total {
                HostState::Up
            } else {
                HostState::Degraded
            };
            HostStatus { state, latency: None }
        })
    }
}
