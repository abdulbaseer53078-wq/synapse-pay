//! Runs the card service against one ISO 8583 acquirer host. Configured by environment variables:
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `CARD_SERVICE_ADDR` | listen address, default `127.0.0.1:7070` (loopback only: see `http`) |
//! | `SIM_HSM_BDK_HEX` | simulated HSM base key, 32 or 64 hex chars (TEST KEY ONLY) |
//! | `HOST_ADDR`, `HOST_SERVER_NAME` | acquirer host `ip:port` and its TLS name |
//! | `HOST_CA`, `HOST_CLIENT_CERT`, `HOST_CLIENT_KEY` | PEM files for mutual TLS to the host |
//! | `HOST_DIALECT` | ISO 8583 dialect JSON (e.g. `iso8583/dialects/synthetic-host.json`) |
//! | `HOST_POOL_SIZE` | connections to the host, default 4 |
//! | `HOST_TIMEOUT_MS` | how long the host gets to answer, default 1500 |
//! | `AUDIT_LOG_PATH` | JSON Lines file for redacted ISO 8583 audit records (required) |

use std::env;
use std::sync::Arc;
use std::time::Duration;

use card_service::flow::{CardFlow, Timeouts};
use card_service::hsm::SimHsm;
use host_connector::audit::JsonLines;
use host_connector::framing::{Framing, LengthHeader};
use host_connector::iso_host::IsoHostConfig;
use host_connector::link::LinkConfig;
use host_connector::pool::{IsoHostPool, PoolConfig};
use iso8583::Dictionary;

fn var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| fail(&format!("{name} is not set")))
}

fn fail(why: &str) -> ! {
    eprintln!("card-service: {why}");
    std::process::exit(2)
}

fn number<T: std::str::FromStr>(name: &str, default: T) -> T {
    env::var(name).ok().map(|v| v.parse().unwrap_or_else(|_| fail(&format!("{name} is not a number"))))
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    let hsm = SimHsm::from_hex(&var("SIM_HSM_BDK_HEX")).unwrap_or_else(|e| fail(&e));
    let dialect = std::fs::read_to_string(var("HOST_DIALECT")).unwrap_or_else(|e| fail(&format!("HOST_DIALECT: {e}")));
    let dictionary = Dictionary::from_json(&dialect).unwrap_or_else(|e| fail(&format!("HOST_DIALECT: {e}")));
    let audit_file = std::fs::OpenOptions::new().create(true).append(true).open(var("AUDIT_LOG_PATH"))
        .unwrap_or_else(|e| fail(&format!("AUDIT_LOG_PATH: {e}")));

    // shortcut: 2-byte binary length header, as the synthetic host uses; make it per-acquirer config.
    let mut iso = IsoHostConfig::new(dictionary, Framing { header: LengthHeader::Binary2, max_len: 8_192 });
    iso.audit = Some(Arc::new(JsonLines::new(audit_file)));
    let link = LinkConfig::new(var("HOST_ADDR"), var("HOST_SERVER_NAME"), var("HOST_CA"), var("HOST_CLIENT_CERT"),
                               var("HOST_CLIENT_KEY"));
    let pool = PoolConfig { size: number("HOST_POOL_SIZE", 4), ..PoolConfig::default() };
    let host = IsoHostPool::start(link, iso, pool).unwrap_or_else(|e| fail(&format!("host link: {e}")));
    let up = host.wait_ready(Duration::from_secs(10)).await;
    eprintln!("card-service: {up} host connection(s) up");

    let timeouts = Timeouts { host: Duration::from_millis(number("HOST_TIMEOUT_MS", 1_500)), ..Timeouts::default() };
    let flow = Arc::new(CardFlow { hsm: Arc::new(hsm), host: Arc::new(host), timeouts });

    let addr = env::var("CARD_SERVICE_ADDR").unwrap_or_else(|_| "127.0.0.1:7070".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap_or_else(|e| fail(&format!("bind {addr}: {e}")));
    // Tests and scripts wait for this exact line.
    println!("LISTENING {}", listener.local_addr().expect("bound"));
    axum::serve(listener, card_service::http::router(flow))
        .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
        .await
        .unwrap_or_else(|e| fail(&format!("server: {e}")));
}
