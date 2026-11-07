//! A scriptable in-memory [`HostConnector`] for tests of anything that sends transactions.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use crate::{BoxFuture, Decision, HostConnector, HostError, HostResponse, HostState, HostStatus, RequestContext,
            Transaction};

/// Answers with scripted results in order, then approves everything. Records every transaction it received.
/// A request whose deadline has already passed gets [`HostError::Timeout`], as a real host would.
pub struct MockHostConnector {
    script: Mutex<VecDeque<Result<HostResponse, HostError>>>,
    received: Mutex<Vec<Transaction>>,
    status: Mutex<HostStatus>,
}

impl Default for MockHostConnector {
    fn default() -> Self {
        Self {
            script: Mutex::default(),
            received: Mutex::default(),
            status: Mutex::new(HostStatus { state: HostState::Up, latency: None }),
        }
    }
}

impl MockHostConnector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues the result for the next transaction (in order, one per transaction).
    pub fn respond_with(&self, result: Result<HostResponse, HostError>) -> &Self {
        self.script.lock().unwrap().push_back(result);
        self
    }

    pub fn set_status(&self, status: HostStatus) {
        *self.status.lock().unwrap() = status;
    }

    /// Every transaction sent so far, in order.
    pub fn received(&self) -> Vec<Transaction> {
        self.received.lock().unwrap().clone()
    }

    /// The default answer once the script runs out.
    pub fn approval() -> HostResponse {
        HostResponse {
            decision: Decision::Approved { authorization_code: "MOCK01".into() },
            response_code: "00".into(),
            host_reference: None,
        }
    }
}

impl HostConnector for MockHostConnector {
    fn send_transaction<'a>(&'a self, ctx: &'a RequestContext, txn: &'a Transaction)
        -> BoxFuture<'a, Result<HostResponse, HostError>> {
        Box::pin(async move {
            self.received.lock().unwrap().push(txn.clone());
            if Instant::now() >= ctx.deadline {
                return Err(HostError::Timeout);
            }
            self.script.lock().unwrap().pop_front().unwrap_or_else(|| Ok(Self::approval()))
        })
    }

    fn check_health(&self) -> BoxFuture<'_, HostStatus> {
        Box::pin(async move { self.status.lock().unwrap().clone() })
    }
}
