//! Internal HTTP API, called only by the API backend. Never expose it: it is not authenticated.
//!
//! shortcut: plain HTTP on loopback. Before production, run it as a sidecar reachable only from the
//! backend (Unix socket or mTLS), in the PCI cardholder-data environment with the HSM.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::extract::{Path, Query};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use host_connector::HostState;
use serde_json::json;

use crate::fleet::Fleet;
use crate::flow::{expiry_yymm, AuthenticateRequest, CardFlow, CardRequest, FlowError};
use crate::vault::{TokenizeRequest, VaultError};

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
        .route("/card/tokens", post(tokenize))
        .route("/card/tokens/index", get(token_index))
        .route("/card/tokens/{token}", delete(revoke_token))
        .route("/card/reversals/{transaction_id}", get(reversal_state))
        .route("/health", get(health))
        .route("/internal/v1/hosts/health", get(fleet_health))
        .with_state(state)
}

async fn transaction(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(mut req): Json<CardRequest>)
    -> Response {
    // The backend sends the id as 32 lowercase hex digits; anything else is ignored rather than logged.
    req.trace_id = headers.get("x-trace-id").and_then(|v| v.to_str().ok())
        .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .map(str::to_owned);
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

#[derive(serde::Deserialize)]
struct TokenizeBody {
    merchant_id: String,
    encrypted_card_data: String,
    card_expiry: String,
    card_network: String,
    #[serde(default)]
    customer_ref: Option<String>,
}

#[derive(serde::Deserialize)]
struct MerchantQuery {
    merchant_id: String,
}

fn no_vault() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"error": "NO_VAULT"}))).into_response()
}

fn vault_error(e: VaultError) -> Response {
    let (code, error, message) = match e {
        VaultError::BadCardData(m) => (StatusCode::UNPROCESSABLE_ENTITY, "BAD_CARD_DATA", m),
        VaultError::BadRequest(m) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", m),
        VaultError::UnknownToken => (StatusCode::NOT_FOUND, "UNKNOWN_TOKEN", "unknown or revoked token".into()),
        VaultError::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, "VAULT_UNAVAILABLE", m),
    };
    (code, Json(json!({"error": error, "message": message}))).into_response()
}

/// Step 29: save a card. The answer is the token and the masked card, never the number.
async fn tokenize(State(state): State<Arc<AppState>>, Json(body): Json<TokenizeBody>) -> Response {
    let Some(vault) = state.flow.vault.as_deref() else { return no_vault() };
    if body.merchant_id.is_empty() || body.merchant_id.len() > 64 {
        return vault_error(VaultError::BadRequest("merchant_id must be 1 to 64 characters".into()));
    }
    if !["VISA", "MASTERCARD", "RUPAY", "AMEX"].contains(&body.card_network.as_str()) {
        return vault_error(VaultError::BadRequest("card_network must be VISA, MASTERCARD, RUPAY or AMEX".into()));
    }
    if expiry_yymm(&body.card_expiry).is_err() {
        return vault_error(VaultError::BadRequest("card_expiry must be MM/YY".into()));
    }
    let pan = match state.flow.hsm.decrypt_pan(&body.encrypted_card_data) {
        Ok(pan) => pan,
        Err(e) => return vault_error(e.into()),
    };
    let req = TokenizeRequest { merchant_id: &body.merchant_id, pan, card_network: &body.card_network,
                                card_expiry: &body.card_expiry, customer_ref: body.customer_ref.as_deref() };
    match vault.tokenize(req).await {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(e) => vault_error(e),
    }
}

async fn revoke_token(State(state): State<Arc<AppState>>, Path(token): Path<String>,
                      Query(q): Query<MerchantQuery>) -> Response {
    let Some(vault) = state.flow.vault.as_deref() else { return no_vault() };
    match vault.revoke(&q.merchant_id, &token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => vault_error(e),
    }
}

/// What an edge node may hold for this merchant (Step 23): references and masked cards, revoked ones included.
async fn token_index(State(state): State<Arc<AppState>>, Query(q): Query<MerchantQuery>) -> Response {
    let Some(vault) = state.flow.vault.as_deref() else { return no_vault() };
    match vault.index(&q.merchant_id).await {
        Ok(tokens) => Json(json!({"tokens": tokens})).into_response(),
        Err(e) => vault_error(e),
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
/// Where an owed reversal stands (PR 3): the API backend's recovery sweep resolves a stuck payment from it.
async fn reversal_state(State(state): State<Arc<AppState>>, Path(transaction_id): Path<String>) -> Response {
    let Some(queue) = &state.flow.reversals else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "NO_REVERSAL_QUEUE"}))).into_response();
    };
    match queue.state(&transaction_id).await {
        Ok(Some(s)) => Json(json!({"transaction_id": transaction_id, "state": s})).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "NOT_QUEUED"}))).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e}))).into_response(),
    }
}

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
