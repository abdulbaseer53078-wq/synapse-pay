//! Internal HTTP API, called only by the API backend. Never expose it: it is not authenticated.
//!
//! shortcut: plain HTTP on loopback. Before production, run it as a sidecar reachable only from the
//! backend (Unix socket or mTLS), in the PCI cardholder-data environment with the HSM.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use host_connector::HostState;
use serde_json::json;

use crate::fleet::Fleet;
use crate::flow::{AuthenticateRequest, CardFlow, CardRequest, FlowError};

/// What the handlers need: the flow that does the work, and the fleet behind it for the per-host health view.
/// The flow's `host` is the same fleet, so a transaction and its health answer can never disagree about which
/// hosts exist.
pub struct AppState {
    pub flow: CardFlow,
    pub fleet: Arc<Fleet>,
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/card/transactions", post(transaction))
        .route("/card/authenticate", post(authenticate))
        .route("/card/checkout-key", get(checkout_key))
        .route("/health", get(health))
        .route("/internal/v1/hosts/health", get(fleet_health))
        .with_state(state)
}

async fn transaction(State(state): State<Arc<AppState>>, Json(req): Json<CardRequest>) -> Response {
    match state.flow.process(&req).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => flow_error(e),
    }
}

fn flow_error(e: FlowError) -> Response {
    match e {
        FlowError::BadCardData(why) => {
            (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "BAD_CARD_DATA", "message": why}))).into_response()
        }
        FlowError::BadRequest(why) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": "BAD_REQUEST", "message": why}))).into_response()
        }
    }
}

async fn authenticate(State(state): State<Arc<AppState>>, Json(req): Json<AuthenticateRequest>) -> Response {
    match state.flow.authenticate(&req) {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(e) => flow_error(e),
    }
}

/// The public key browsers and apps encrypt card data to. Public by design; the backend republishes it.
async fn checkout_key(State(state): State<Arc<AppState>>) -> Response {
    match state.flow.hsm.checkout_public_jwk() {
        Some(jwk) => ([("content-type", "application/json")], jwk).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "NO_CHECKOUT_KEY"}))).into_response(),
    }
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let status = state.flow.host.check_health().await;
    let state = match status.state {
        HostState::Up => "UP",
        HostState::Degraded => "DEGRADED",
        HostState::Down => "DOWN",
    };
    // DEGRADED is still serving: only Down takes the service out of the load balancer.
    let code = if status.state == HostState::Down { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK };
    (code, Json(json!({"host": state}))).into_response()
}

/// One row per acquirer, for the backend's health poller (Step 14.8). A pool with no live socket is DOWN; the
/// fleet itself is only Degraded when some of its hosts are. `latency_ms` stays absent until the pool measures it.
async fn fleet_health(State(state): State<Arc<AppState>>) -> Json<Vec<serde_json::Value>> {
    let mut results = Vec::with_capacity(state.fleet.pools.len());
    for (host_id, pool) in &state.fleet.pools {
        results.push(json!({
            "host_id": host_id,
            "status": if pool.connections_up() > 0 { "UP" } else { "DOWN" },
        }));
    }
    // A HashMap has no order; sort so a poller, a log line and a test all see the same list.
    results.sort_by(|a, b| a["host_id"].as_str().cmp(&b["host_id"].as_str()));
    Json(results)
}
