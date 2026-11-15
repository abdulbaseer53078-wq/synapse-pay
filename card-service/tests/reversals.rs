//! Flaw #3: outside the sandbox (F-16) an owed reversal is still recorded durably, without card data, and the
//! record survives a restart as MANUAL for a person. Skipped when no Postgres is reachable (VAULT_TEST_DATABASE_URL).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use card_service::fleet::Fleet;
use card_service::hsm::{Hsm, SimHsm};
use card_service::reversals::ReversalQueue;
use host_connector::framing::{Framing, LengthHeader};
use host_connector::iso_host::{IsoHostConfig, Original};
use host_connector::link::LinkConfig;
use host_connector::pool::{IsoHostPool, PoolConfig};
use host_connector::stan::StanSource;
use host_connector::{Card, Transaction, TransactionKind};
use iso8583::Dictionary;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};

const DIALECT: &str = include_str!("../../iso8583/dialects/synthetic-host.json");
const BDK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const PAN: &str = "4111111111111111";

/// A fleet of one host that is down, which has sent `txn_1`'s purchase: exactly the state after a timeout
/// whose in-line reversals all failed.
fn fleet(dir: &std::path::Path) -> Arc<Fleet> {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["synapsepay-card-service".to_string()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let (ca_path, cert_path, key_path) = (dir.join("ca.pem"), dir.join("client.pem"), dir.join("client-key.pem"));
    std::fs::write(&ca_path, ca.pem()).unwrap();
    std::fs::write(&cert_path, leaf.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let link = LinkConfig::new("127.0.0.1:1", "localhost", ca_path, cert_path, key_path);
    let iso = IsoHostConfig::new(Dictionary::from_json(DIALECT).unwrap(),
                                 Framing { header: LengthHeader::Binary2, max_len: 8_192 });
    let pool = IsoHostPool::start(link, iso, PoolConfig { size: 1, ..PoolConfig::default() }).unwrap();
    let fleet = Fleet::new(HashMap::from([("acq_a".to_string(), Arc::new(pool))]), Arc::new(StanSource::single()));
    let sent = Original { mti: "0200".into(), stan: "000123".into(), transmitted: "1114120000".into() };
    assert!(fleet.restore_original("acq_a", "txn_1", sent));
    Arc::new(fleet)
}

#[tokio::test]
async fn an_owed_reversal_outside_the_sandbox_survives_a_restart_without_card_data() {
    let admin = std::env::var("VAULT_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".into());
    let Ok((client, conn)) = tokio_postgres::connect(&admin, tokio_postgres::NoTls).await else {
        eprintln!("skipped: no Postgres at {admin}");
        return;
    };
    tokio::spawn(conn);
    let db = format!("synapse_reversal_test_{}", std::process::id());
    client.batch_execute(&format!("DROP DATABASE IF EXISTS {db}")).await.unwrap();
    client.batch_execute(&format!("CREATE DATABASE {db}")).await.unwrap();
    let url = format!("{}/{db}", admin.rsplit_once('/').unwrap().0);

    let dir = std::env::temp_dir().join(format!("synapse_reversal_test_{}", std::process::id()));
    let fleet = fleet(&dir);
    let hsm: Arc<dyn Hsm> = Arc::new(SimHsm::from_hex(BDK).unwrap());
    let purchase = Transaction {
        transaction_id: "txn_1".into(),
        kind: TransactionKind::Purchase,
        amount_minor: 50_000,
        currency: "INR".into(),
        merchant_id: "m_1".into(),
        terminal_id: "t_1".into(),
        card: Card { pan: PAN.into(), expiry: "2812".into(), icc: None },
    };

    let queue = ReversalQueue::connect(&url, hsm.clone(), fleet.clone(), Duration::from_millis(100), false)
        .await.unwrap();
    queue.enqueue(&purchase).await.unwrap();
    drop(queue);

    // Restart: a fresh connection (and migration run) finds the record, and leaves it for a person.
    let queue = ReversalQueue::connect(&url, hsm, fleet, Duration::from_millis(100), false).await.unwrap();
    assert_eq!(queue.state("txn_1").await.unwrap().as_deref(), Some("MANUAL"));
    assert_eq!(queue.run_once().await.unwrap(), 0, "nothing to resend without card data");

    let (rows, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(conn);
    let row = rows.query_one("SELECT host_id, original_stan, sealed_pan IS NULL AND card_expiry IS NULL, t::text \
                              FROM pending_reversals t", &[]).await.unwrap();
    assert_eq!((row.get::<_, String>(0), row.get::<_, String>(1), row.get::<_, bool>(2)),
               ("acq_a".to_string(), "000123".to_string(), true));
    assert!(!row.get::<_, String>(3).contains(PAN), "card number at rest");

    drop(rows);
    let _ = client.batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).await;
    let _ = std::fs::remove_dir_all(dir);
}

// Serialise env-var mutation so these two tests don't race each other.
static ENV_MUTEX: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_MUTEX.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap_or_else(|p| p.into_inner())
}

/// When neither REVERSAL_DATABASE_URL nor VAULT_DATABASE_URL is set, the main.rs
/// `or_else` chain returns Err, so reversals = None and startup does not panic.
#[test]
fn test_queue_disabled_when_no_url() {
    let _guard = env_lock();
    let prev_r = std::env::var("REVERSAL_DATABASE_URL").ok();
    let prev_v = std::env::var("VAULT_DATABASE_URL").ok();
    // SAFETY: serialised by ENV_MUTEX; no other thread reads these vars while the lock is held.
    unsafe {
        std::env::remove_var("REVERSAL_DATABASE_URL");
        std::env::remove_var("VAULT_DATABASE_URL");
    }

    // Mirror main.rs line 211: env::var("REVERSAL_DATABASE_URL").or_else(|_| env::var("VAULT_DATABASE_URL"))
    let resolved = std::env::var("REVERSAL_DATABASE_URL")
        .or_else(|_| std::env::var("VAULT_DATABASE_URL"));
    assert!(resolved.is_err(), "both absent → Err → reversals = None → no startup panic");

    unsafe {
        if let Some(v) = prev_r { std::env::set_var("REVERSAL_DATABASE_URL", v); }
        if let Some(v) = prev_v { std::env::set_var("VAULT_DATABASE_URL", v); }
    }
}

/// REVERSAL_DATABASE_URL wins over VAULT_DATABASE_URL; VAULT_DATABASE_URL is the fallback
/// when REVERSAL_DATABASE_URL is absent.
#[test]
fn test_reversal_url_takes_priority_over_vault_url() {
    let _guard = env_lock();
    let prev_r = std::env::var("REVERSAL_DATABASE_URL").ok();
    let prev_v = std::env::var("VAULT_DATABASE_URL").ok();
    // SAFETY: serialised by ENV_MUTEX.
    unsafe {
        std::env::set_var("REVERSAL_DATABASE_URL", "postgresql://reversal-host/reversal_db");
        std::env::set_var("VAULT_DATABASE_URL", "postgresql://vault-host/vault_db");
    }

    let resolved = std::env::var("REVERSAL_DATABASE_URL")
        .or_else(|_| std::env::var("VAULT_DATABASE_URL"))
        .unwrap();
    assert_eq!(resolved, "postgresql://reversal-host/reversal_db",
               "REVERSAL_DATABASE_URL takes priority");

    // Fallback: REVERSAL absent, VAULT present.
    unsafe { std::env::remove_var("REVERSAL_DATABASE_URL"); }
    let fallback = std::env::var("REVERSAL_DATABASE_URL")
        .or_else(|_| std::env::var("VAULT_DATABASE_URL"))
        .unwrap();
    assert_eq!(fallback, "postgresql://vault-host/vault_db",
               "falls back to VAULT_DATABASE_URL when REVERSAL_DATABASE_URL is absent");

    unsafe {
        std::env::remove_var("REVERSAL_DATABASE_URL");
        std::env::remove_var("VAULT_DATABASE_URL");
        if let Some(v) = prev_r { std::env::set_var("REVERSAL_DATABASE_URL", v); }
        if let Some(v) = prev_v { std::env::set_var("VAULT_DATABASE_URL", v); }
    }
}
