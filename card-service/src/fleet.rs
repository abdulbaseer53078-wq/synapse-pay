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
//! * **Cascade only when the outcome is unknown.** A host that times out may have approved the payment, so the
//!   next host is tried; a host that answers with a decline is the answer, and retrying it elsewhere would only
//!   ask the same question twice.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use host_connector::pool::IsoHostPool;
use host_connector::stan::StanSource;
use host_connector::{BoxFuture, HostConnector, HostError, HostResponse, HostState, HostStatus, RequestContext,
                     Transaction};

pub struct Fleet {
    pub pools: HashMap<String, Arc<IsoHostPool>>,
    stans: Arc<StanSource>,
}

impl Fleet {
    /// `stans` must be the source the pools were started with (`IsoHostPool::start_with_stans`): then a
    /// transaction's STAN can't collide with a pool's echo, and slots keep other card-service instances apart.
    pub fn new(pools: HashMap<String, Arc<IsoHostPool>>, stans: Arc<StanSource>) -> Self {
        Self { pools, stans }
    }

    fn mint_stan(&self) -> String {
        self.stans.next()
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

            // Only hosts that exist and have a live socket: a skipped host must not consume a timeout slice.
            // Ordered as the caller asked, so the routing engine's preference order survives.
            let candidates: Vec<(&String, &Arc<IsoHostPool>)> = hint.iter()
                .filter_map(|host_id| self.pools.get(host_id).map(|pool| (host_id, pool)))
                .filter(|(_, pool)| pool.connections_up() > 0)
                .collect();
            if candidates.is_empty() {
                return Err(HostError::Unavailable("no host in the hint is up".into()));
            }

            // Split the caller's deadline across the hosts that are left. Without this, the first host can
            // spend the whole budget and the backup never gets a chance to answer. The caller still gets one
            // overall deadline; it is the fleet's job to divide it, not to multiply it by the number of hosts.
            let total = candidates.len();
            let mut unknown: Option<HostError> = None;
            for (index, (host_id, pool)) in candidates.into_iter().enumerate() {
                let remaining = ctx.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let mut attempt = ctx.clone();
                attempt.deadline = Instant::now() + remaining / (total - index) as u32;
                match pool.send_with_stan(&attempt, txn, stan.clone()).await {
                    Ok(mut response) => {
                        // The truth for the audit trail: not the host we asked for, the host that answered.
                        response.host_used = host_id.clone();
                        return Ok(response);
                    }
                    Err(error) if error.outcome_unknown() => {
                        // The host may have acted. Remember it: a later "unavailable" must not turn an unknown
                        // outcome into a clean failure the caller would happily retry.
                        unknown = Some(error);
                    }
                    Err(error) => return Err(unknown.unwrap_or(error)),
                }
            }
            Err(unknown.unwrap_or_else(|| {
                HostError::Unavailable("no host in the hint accepted the transaction before the deadline".into())
            }))
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
