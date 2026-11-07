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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use host_connector::pool::IsoHostPool;
use host_connector::{BoxFuture, HostConnector, HostError, HostResponse, HostState, HostStatus, RequestContext,
                     Transaction};

pub struct Fleet {
    pub pools: HashMap<String, Arc<IsoHostPool>>,
    next_stan: AtomicU32,
}

impl Fleet {
    pub fn new(pools: HashMap<String, Arc<IsoHostPool>>) -> Self {
        Self { pools, next_stan: AtomicU32::new(1) }
    }

    /// Same formatting as `IsoHostConnector::next_stan`, so a STAN minted here can never collide with one minted
    /// by a connector: six digits, 1..=999_999.
    fn mint_stan(&self) -> String {
        let value = self.next_stan.fetch_add(1, Ordering::Relaxed);
        format!("{:06}", (value % 999_999) + 1)
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

            for host_id in hint {
                let Some(pool) = self.pools.get(&host_id) else { continue };
                if pool.connections_up() == 0 {
                    continue; // every socket to this host is down; the link layer is already reconnecting
                }
                match pool.send_with_stan(ctx, txn, stan.clone()).await {
                    Ok(mut response) => {
                        // The truth for the audit trail: not the host we asked for, the host that answered.
                        response.host_used = host_id;
                        return Ok(response);
                    }
                    Err(error) if error.outcome_unknown() => continue, // may have been approved: try the next
                    Err(error) => return Err(error), // a clean "not delivered" / hard stop
                }
            }
            Err(HostError::Unavailable("no host in the hint accepted the transaction".into()))
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
