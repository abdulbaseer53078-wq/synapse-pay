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

use crate::flow::{CardFlow, CardRequest, FlowError};

pub fn router(flow: Arc<CardFlow>) -> Router {
    Router::new()
        .route("/card/transactions", post(transaction))
        .route("/health", get(health))
        .with_state(flow)
}

async fn transaction(State(flow): State<Arc<CardFlow>>, Json(req): Json<CardRequest>) -> Response {
    match flow.process(&req).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(FlowError::BadCardData(why)) => {
            (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "BAD_CARD_DATA", "message": why}))).into_response()
        }
        Err(FlowError::BadRequest(why)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": "BAD_REQUEST", "message": why}))).into_response()
        }
    }
}

async fn health(State(flow): State<Arc<CardFlow>>) -> Response {
    let status = flow.host.check_health().await;
    let state = match status.state {
        HostState::Up => "UP",
        HostState::Degraded => "DEGRADED",
        HostState::Down => "DOWN",
    };
    let code = if status.state == HostState::Down { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK };
    (code, Json(json!({"host": state}))).into_response()
}
