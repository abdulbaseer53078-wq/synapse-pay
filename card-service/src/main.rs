//! Runs the card service against one or more ISO 8583 acquirer hosts. Configured by environment variables:
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `CARD_SERVICE_ADDR` | listen address, default `127.0.0.1:7070` (loopback only: see `http`) |
//! | `SIM_HSM_BDK_HEX` | simulated HSM base key, 32 or 64 hex chars (TEST KEY ONLY) |
//! | `SIM_HSM_CHECKOUT_KEY` | PKCS#8 PEM file with the P-256 checkout key browsers encrypt to; generated (and lost on restart) if unset |
//! | `HOSTS` | comma-separated acquirer IDs to run as a fleet, e.g. `acquirer_a,acquirer_b`. Empty: single-host mode |
//! | `ACQUIRER_ID` | the host's ID in single-host mode, default `acquirer_a` |
//! | `HOST_ADDR`, `HOST_SERVER_NAME` | acquirer host `ip:port` and its TLS name |
//! | `HOST_CA`, `HOST_CLIENT_CERT`, `HOST_CLIENT_KEY` | PEM files for mutual TLS to the host |
//! | `HOST_DIALECT` | ISO 8583 dialect JSON (e.g. `iso8583/dialects/synthetic-host.json`) |
//! | `HOST_POOL_SIZE` | connections to the host, default 4 |
//! | `HOST_TIMEOUT_MS` | how long each host gets to answer, default 1500 |
//! | `AUDIT_LOG_PATH` | JSON Lines file for redacted ISO 8583 audit records (required) |
//! | `STAN_INSTANCE`, `STAN_INSTANCES` | this process's STAN slot, unique across every card-service in every region; default 0 of 1 |
//! | `VAULT_DATABASE_URL` | card-service's own Postgres: the token vault and the durable reversal queue |
//! | `CARD_DATA_STORAGE` | `sandbox` to allow the two above; startup fails without it (frozen pending PCI review) |
//! | `REVERSAL_RETRY_MS` | how often owed reversals are resent, default 10000 |
//!
//! In fleet mode every host reads `<ID>_ADDR` (required). The shared `HOST_SERVER_NAME`, `HOST_CA`,
//! `HOST_CLIENT_CERT`, `HOST_CLIENT_KEY`, `HOST_DIALECT` and `HOST_POOL_SIZE` apply to every host, and
//! `<ID>_SERVER_NAME`, `<ID>_CA`, `<ID>_CLIENT_CERT`, `<ID>_CLIENT_KEY`, `<ID>_DIALECT` or `<ID>_POOL_SIZE`
//! override one of them. One certificate set usually serves every acquirer, so only the address has to be
//! named per host.
//!
//! The fleet is the only `HostConnector` the flow sees: one host or five, the request path is identical.

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;

use card_service::fleet::Fleet;
use card_service::flow::{CardFlow, Timeouts};
use card_service::reversals::ReversalQueue;
use card_service::hsm::{Hsm, SimHsm};
use card_service::http::AppState;
use card_service::vault::{MemoryStore, NetworkTokenProvider, NoNetworkTokens, SimulatedTokenService, Vault, VaultStore};
use card_service::vault_pg::PgStore;
use host_connector::audit::{AuditSink, JsonLines};
use host_connector::framing::{Framing, LengthHeader};
use host_connector::iso_host::IsoHostConfig;
use host_connector::link::LinkConfig;
use host_connector::pool::{IsoHostPool, PoolConfig};
use host_connector::stan::StanSource;
use host_connector::HostConnector;
use iso8583::Dictionary;

fn var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| fail(&format!("{name} is not set")))
}

/// An optional variable: unset and empty are the same thing, so an exported-but-blank value doesn't become a path.
fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn fail(why: &str) -> ! {
    eprintln!("card-service: {why}");
    std::process::exit(2)
}

fn number<T: std::str::FromStr>(name: &str, default: T) -> T {
    optional(name).map(|v| v.parse().unwrap_or_else(|_| fail(&format!("{name} is not a number"))))
        .unwrap_or(default)
}

/// A host's value: `<PREFIX>_<KEY>` when in fleet mode, else the shared `HOST_<KEY>`. This keeps the single-host
/// deployment (and its e2e fixture) working unchanged while letting a fleet override one host at a time.
///
/// `ADDR` is the exception: a fleet host must name its own address, so it never falls back to `HOST_ADDR` (that
/// would point every acquirer at one socket, which is the failure this step exists to remove).
fn host_var(prefix: Option<&str>, key: &str) -> Option<String> {
    if let Some(prefix) = prefix {
        if let Some(value) = optional(&format!("{prefix}_{key}")) {
            return Some(value);
        }
        if key == "ADDR" {
            return None;
        }
    }
    optional(&format!("HOST_{key}"))
}

fn host_var_or_fail(prefix: Option<&str>, key: &str, host: &str) -> String {
    host_var(prefix, key).unwrap_or_else(|| fail(&format!("{} is not set", match prefix {
        Some(p) if key != "ADDR" => format!("{p}_{key} or HOST_{key} (for host {host})"),
        Some(p) => format!("{p}_{key} (for host {host})"),
        None => format!("HOST_{key} (for host {host})"),
    })))
}

fn host_pool_size(prefix: Option<&str>) -> usize {
    host_var(prefix, "POOL_SIZE")
        .map(|v| v.parse().unwrap_or_else(|_| fail("POOL_SIZE is not a number")))
        .unwrap_or(4)
}

/// Builds one acquirer's link and ISO 8583 settings and starts its pool. The audit sink is shared: one JSON
/// Lines file is the record of every message to every acquirer, and `JsonLines` serialises its own writes.
fn start_pool(host: &str, prefix: Option<&str>, audit: Arc<dyn AuditSink>, stans: Arc<StanSource>) -> IsoHostPool {
    let addr = host_var_or_fail(prefix, "ADDR", host);
    let server_name = host_var_or_fail(prefix, "SERVER_NAME", host);
    let ca = host_var_or_fail(prefix, "CA", host);
    let client_cert = host_var_or_fail(prefix, "CLIENT_CERT", host);
    let client_key = host_var_or_fail(prefix, "CLIENT_KEY", host);
    let dialect_path = host_var_or_fail(prefix, "DIALECT", host);
    let dialect = std::fs::read_to_string(&dialect_path)
        .unwrap_or_else(|e| fail(&format!("{dialect_path} (dialect for {host}): {e}")));
    let dictionary = Dictionary::from_json(&dialect)
        .unwrap_or_else(|e| fail(&format!("{dialect_path} (dialect for {host}): {e}")));

    // shortcut: 2-byte binary length header, as the synthetic host uses; make it per-acquirer config.
    let mut iso = IsoHostConfig::new(dictionary, Framing { header: LengthHeader::Binary2, max_len: 8_192 });
    iso.audit = Some(audit);
    let link = LinkConfig::new(addr, server_name, ca, client_cert, client_key);
    IsoHostPool::start_with_stans(link, iso, PoolConfig { size: host_pool_size(prefix), ..PoolConfig::default() }, stans)
        .unwrap_or_else(|e| fail(&format!("host link for {host}: {e}")))
}

#[tokio::main]
async fn main() {
    // F-16 freeze: storing card data (vault, reversal queue) waits for the QSA review of docs/card-data-flow.md.
    // Until then it is sandbox only, and asking for it without saying so stops startup rather than run silently.
    let card_storage = env::var("CARD_DATA_STORAGE").as_deref() == Ok("sandbox");
    if !card_storage && (env::var("VAULT_DATABASE_URL").is_ok() || env::var("VAULT_IN_MEMORY").is_ok()) {
        fail("card-data storage is frozen pending PCI review: set CARD_DATA_STORAGE=sandbox (never in production) \
              or unset VAULT_DATABASE_URL and VAULT_IN_MEMORY");
    }
    let checkout = match env::var("SIM_HSM_CHECKOUT_KEY") {
        Ok(path) => {
            use p256::pkcs8::DecodePrivateKey;
            let pem = std::fs::read_to_string(&path).unwrap_or_else(|e| fail(&format!("SIM_HSM_CHECKOUT_KEY: {e}")));
            p256::SecretKey::from_pkcs8_pem(&pem).unwrap_or_else(|_| fail("SIM_HSM_CHECKOUT_KEY is not a P-256 PKCS#8 PEM"))
        }
        Err(_) => {
            eprintln!("card-service: SIM_HSM_CHECKOUT_KEY not set; generated a checkout key that lasts until restart");
            p256::SecretKey::random(&mut rand_core::OsRng)
        }
    };
    let hsm = SimHsm::from_hex(&var("SIM_HSM_BDK_HEX")).unwrap_or_else(|e| fail(&e)).with_checkout_key(checkout);
    let audit_file = std::fs::OpenOptions::new().create(true).append(true).open(var("AUDIT_LOG_PATH"))
        .unwrap_or_else(|e| fail(&format!("AUDIT_LOG_PATH: {e}")));
    let audit: Arc<dyn AuditSink> = Arc::new(JsonLines::new(audit_file));

    // Two card-services with the same slot would send the acquirer duplicate STANs: every deployment must give
    // each running instance its own STAN_INSTANCE (infra/ecs does, per region).
    let stans = Arc::new(StanSource::new(number("STAN_INSTANCE", 0), number("STAN_INSTANCES", 1))
        .unwrap_or_else(|e| fail(&e)));
    let mut pools = HashMap::new();
    let hosts = optional("HOSTS").unwrap_or_default();
    if hosts.trim().is_empty() {
        // Single-host fallback: the e2e baseline and every existing deployment keep this exact shape.
        let acquirer_id = env::var("ACQUIRER_ID").unwrap_or_else(|_| "acquirer_a".to_string());
        let pool = start_pool(&acquirer_id, None, audit.clone(), stans.clone());
        pools.insert(acquirer_id, Arc::new(pool));
    } else {
        for raw in hosts.split(',') {
            let host = raw.trim();
            if host.is_empty() {
                continue;
            }
            if pools.contains_key(host) {
                fail(&format!("HOSTS lists {host} twice"));
            }
            // ACQUIRER-A_ADDR is not a legal environment variable name; use the same underscore mapping the
            // other host variables use.
            let prefix: String = host.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
                .collect();
            let pool = start_pool(host, Some(&prefix), audit.clone(), stans.clone());
            pools.insert(host.to_string(), Arc::new(pool));
        }
        if pools.is_empty() {
            fail("HOSTS is set but names no host");
        }
    }

    for (host_id, pool) in &pools {
        let up = pool.wait_ready(Duration::from_secs(10)).await;
        eprintln!("card-service: {host_id}: {up} host connection(s) up");
    }

    let timeouts = Timeouts { host: Duration::from_millis(number("HOST_TIMEOUT_MS", 1_500)), ..Timeouts::default() };
    let fleet = Arc::new(Fleet::new(pools, stans));
    // The fleet *is* the host connector: one host or five, CardFlow calls the same trait method.
    let host: Arc<dyn HostConnector> = fleet.clone();
    let hsm: Arc<dyn Hsm> = Arc::new(hsm);
    // Step 29: the token vault, in its own database. VAULT_IN_MEMORY=1 is for the sandbox only: tokens vanish on exit.
    let network_tokens: Arc<dyn NetworkTokenProvider> = match env::var("NETWORK_TOKENS").as_deref() {
        Ok("simulated") => Arc::new(SimulatedTokenService::default()),
        _ => Arc::new(NoNetworkTokens),
    };
    let store: Option<Arc<dyn VaultStore>> = if let Ok(url) = env::var("VAULT_DATABASE_URL") {
        Some(Arc::new(PgStore::connect(&url).await.unwrap_or_else(|e| fail(&format!("vault database: {e}")))))
    } else if env::var("VAULT_IN_MEMORY").as_deref() == Ok("1") {
        Some(Arc::new(MemoryStore::default()))
    } else {
        None
    };
    let vault = store.map(|store| Arc::new(Vault { store, hsm: hsm.clone(), network_tokens }));
    eprintln!("card-service: token vault {}", if vault.is_some() { "on" } else { "off" });
    // PR 3: owed reversals outlive the request, in the same private database. Without it they are only logged.
    let reversals = match env::var("VAULT_DATABASE_URL") {
        Ok(url) => {
            let queue = ReversalQueue::connect(&url, hsm.clone(), fleet.clone(), timeouts.reversal).await
                .unwrap_or_else(|e| fail(&format!("reversal queue database: {e}")));
            let queue = Arc::new(queue);
            tokio::spawn(queue.clone().run(Duration::from_millis(number("REVERSAL_RETRY_MS", 10_000))));
            Some(queue)
        }
        Err(_) => None,
    };
    eprintln!("card-service: reversal queue {}", if reversals.is_some() { "on" } else { "off" });
    let flow = CardFlow { hsm, host, timeouts, vault, reversals };

    let state = Arc::new(AppState { flow, fleet });
    let addr = env::var("CARD_SERVICE_ADDR").unwrap_or_else(|_| "127.0.0.1:7070".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap_or_else(|e| fail(&format!("bind {addr}: {e}")));
    // Tests and scripts wait for this exact line.
    println!("LISTENING {}", listener.local_addr().expect("bound"));
    axum::serve(listener, card_service::http::app(state))
        .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
        .await
        .unwrap_or_else(|e| fail(&format!("server: {e}")));
}
