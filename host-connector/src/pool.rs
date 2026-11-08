//! Connection pool for one ISO 8583 host (Task 4.6).
//!
//! Opens `size` mTLS connections at startup. Each transaction checks out one idle connection, uses it for
//! exactly one request/response, and returns it: never two requests on a connection at once. Every idle
//! connection sends an 0800 echo each `echo_interval`; a failed echo resets that socket.
//!
//! All connections draw STANs from one counter, so no two in-flight requests to the host share a STAN.

use std::collections::VecDeque;
use crate::stan::StanSource;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use crate::iso_host::{IsoHostConfig, IsoHostConnector, Originals};
use crate::link::{Link, LinkConfig, LinkError, LinkState};
use crate::{BoxFuture, HostConnector, HostError, HostResponse, HostState, HostStatus, RequestContext, Transaction};

#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Connections to open at startup.
    pub size: usize,
    /// How often an idle connection sends an 0800 echo.
    pub echo_interval: Duration,
    /// How long an echo may take before the connection is considered dead.
    pub echo_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self { size: 8, echo_interval: Duration::from_secs(30), echo_timeout: Duration::from_secs(5) }
    }
}

struct Shared {
    conns: Vec<IsoHostConnector>,
    idle: Mutex<VecDeque<usize>>,
    /// One permit per idle connection: waiting for a permit is waiting for a free connection.
    permits: Arc<Semaphore>,
}

/// Exclusive use of one connection; returns it to the pool when dropped.
struct Checkout<'a> {
    shared: &'a Shared,
    index: usize,
    _permit: OwnedSemaphorePermit, // released after `drop` below has put the index back
}

impl Drop for Checkout<'_> {
    fn drop(&mut self) {
        self.shared.idle.lock().unwrap().push_back(self.index);
    }
}

impl Shared {
    fn is_up(&self, index: usize) -> bool {
        matches!(self.conns[index].link().state(), LinkState::Up { .. })
    }

    /// Waits until a connection is free or `deadline` passes. Prefers connections that are up.
    async fn checkout(&self, deadline: Instant) -> Option<Checkout<'_>> {
        let permit = tokio::time::timeout_at(deadline.into(), self.permits.clone().acquire_owned()).await.ok()?.ok()?;
        let mut idle = self.idle.lock().unwrap();
        let pos = idle.iter().position(|&i| self.is_up(i)).unwrap_or(0);
        let index = idle.remove(pos).expect("a permit means an idle connection");
        Some(Checkout { shared: self, index, _permit: permit })
    }

    /// This particular connection, only if it's idle right now.
    fn try_checkout(&self, index: usize) -> Option<Checkout<'_>> {
        let permit = self.permits.clone().try_acquire_owned().ok()?;
        let mut idle = self.idle.lock().unwrap();
        let pos = idle.iter().position(|&i| i == index)?; // busy: the permit is released unused
        idle.remove(pos);
        Some(Checkout { shared: self, index, _permit: permit })
    }
}

pub struct IsoHostPool {
    shared: Arc<Shared>,
    echoes: Vec<JoinHandle<()>>,
}

impl IsoHostPool {
    /// Opens `pool.size` connections (they connect in the background; see [`wait_ready`](Self::wait_ready))
    /// and starts their echo loops. Must be called inside a Tokio runtime.
    pub fn start(link: LinkConfig, iso: IsoHostConfig, pool: PoolConfig) -> Result<Self, LinkError> {
        Self::start_with_stans(link, iso, pool, Arc::new(StanSource::single()))
    }

    /// Like `start`, drawing echo STANs from `stans`, the source the process's transactions also use, so an
    /// echo and a payment can never carry the same STAN to the host.
    pub fn start_with_stans(link: LinkConfig, iso: IsoHostConfig, pool: PoolConfig, stans: Arc<StanSource>)
        -> Result<Self, LinkError> {
        let iso = Arc::new(iso);
        let originals = Originals::default();
        let conns = (0..pool.size.max(1))
            .map(|_| {
                let (link, events) = Link::start(link.clone())?;
                Ok(IsoHostConnector::with_stans(link, events, iso.clone(), stans.clone(), originals.clone()))
            })
            .collect::<Result<Vec<_>, LinkError>>()?;
        let size = conns.len();
        let shared = Arc::new(Shared {
            conns,
            idle: Mutex::new((0..size).collect()),
            permits: Arc::new(Semaphore::new(size)),
        });
        let echoes = (0..size).map(|i| tokio::spawn(echo_loop(shared.clone(), i, pool))).collect();
        Ok(Self { shared, echoes })
    }

    /// Waits up to `timeout` for every connection to come up; returns how many are up.
    pub async fn wait_ready(&self, timeout: Duration) -> usize {
        let deadline = Instant::now() + timeout;
        for conn in &self.shared.conns {
            conn.link().wait_up(deadline.saturating_duration_since(Instant::now())).await;
        }
        self.connections_up()
    }

    pub fn connections_up(&self) -> usize {
        (0..self.shared.conns.len()).filter(|&i| self.shared.is_up(i)).count()
    }

    /// Send with a caller-supplied STAN, so a fleet-level retry can reuse one across hosts.
    ///
    /// The STAN is minted where the transaction enters the system (card-service), not here: two STANs for one
    /// payment are two transactions on the wire, and only one of them reconciles against the clearing file.
    pub async fn send_with_stan(&self, ctx: &RequestContext, txn: &Transaction, stan: String)
        -> Result<HostResponse, HostError> {
        let Some(conn) = self.shared.checkout(ctx.deadline).await else {
            return Err(HostError::Unavailable("no free connection before the deadline".into()));
        };
        // The checkout returns the connection to the pool when it drops at the end of this scope.
        self.shared.conns[conn.index].send_with_stan(ctx, txn, stan).await
    }
}

impl Drop for IsoHostPool {
    fn drop(&mut self) {
        for echo in &self.echoes {
            echo.abort();
        }
    }
}

impl HostConnector for IsoHostPool {
    fn send_transaction<'a>(&'a self, ctx: &'a RequestContext, txn: &'a Transaction)
        -> BoxFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async move {
            let Some(conn) = self.shared.checkout(ctx.deadline).await else {
                return Err(HostError::Unavailable("no free connection before the deadline".into()));
            };
            self.shared.conns[conn.index].send_transaction(ctx, txn).await
        })
    }

    fn check_health(&self) -> BoxFuture<'_, HostStatus> {
        Box::pin(async move {
            let (up, size) = (self.connections_up(), self.shared.conns.len());
            let state = match up {
                0 => HostState::Down,
                n if n == size => HostState::Up,
                _ => HostState::Degraded,
            };
            HostStatus { state, latency: None }
        })
    }
}

/// Every `echo_interval`: if connection `index` is idle and up, send an 0800; if that fails, reset the socket.
async fn echo_loop(shared: Arc<Shared>, index: usize, pool: PoolConfig) {
    let mut tick = tokio::time::interval(pool.echo_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // the first tick is immediate; the connection was just opened
    loop {
        tick.tick().await;
        let Some(_conn) = shared.try_checkout(index) else { continue }; // busy: traffic is its own heartbeat
        if !shared.is_up(index) {
            continue; // already reconnecting
        }
        let conn = &shared.conns[index];
        let ctx = RequestContext::with_timeout(pool.echo_timeout, format!("echo-{index}"));
        if conn.echo(&ctx).await.is_err() {
            conn.link().reconnect().await;
        }
    }
}
