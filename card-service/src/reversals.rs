//! The durable reversal queue (PR 3).
//!
//! [`CardFlow`](crate::flow::CardFlow) reverses an unknown outcome in-line, a few times. If every attempt fails,
//! the reversal is owed but nobody would send it, and the in-memory record of the original dies with the
//! process. This saves it: card number sealed by the HSM (bound to the transaction id), the original's MTI, STAN
//! and DE 7, and the host that holds it. A background loop puts the original back and resends the reversal to
//! that host until it answers, then wipes the card data. The API backend asks [`ReversalQueue::state`] to
//! resolve the payment.
//!
//! A reversal is safe to repeat, so a resend after a crash, or from two instances at once, is harmless.

use std::sync::Arc;
use std::time::Duration;

use host_connector::iso_host::Original;
use host_connector::{Card, Decision, HostConnector, RequestContext, Transaction, TransactionKind};
use tokio_postgres::{Client, NoTls};

use crate::fleet::Fleet;
use crate::hsm::{ClearPan, Hsm};

pub const MIGRATION: &str = include_str!("../migrations/002_reversal_queue.sql");

/// DE 39 "25": the host has no record of the original, so it never charged the card.
const UNABLE_TO_LOCATE_ORIGINAL: &str = "25";

pub struct ReversalQueue {
    client: Client,
    hsm: Arc<dyn Hsm>,
    fleet: Arc<Fleet>,
    timeout: Duration,
}

/// Postgres's own message (never parameter values), not the driver's bare "db error".
fn db(e: tokio_postgres::Error) -> String {
    format!("reversal queue database: {}", e.as_db_error().map_or_else(|| e.to_string(), |d| d.message().to_owned()))
}

/// The HSM binding for a queued card number: not a vault token, so a ciphertext can't be moved between tables.
fn binding(transaction_id: &str) -> String {
    format!("reversal:{transaction_id}")
}

impl ReversalQueue {
    /// Connects and applies the migration (idempotent).
    /// shortcut: one connection, no TLS, like the vault's (same private database); pool and TLS with RDS.
    pub async fn connect(url: &str, hsm: Arc<dyn Hsm>, fleet: Arc<Fleet>, timeout: Duration)
        -> Result<Self, String> {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("reversal queue database connection closed: {e}");
            }
        });
        client.batch_execute(MIGRATION).await.map_err(|e| e.to_string())?;
        Ok(Self { client, hsm, fleet, timeout })
    }

    /// Saves the reversal of `original` (a purchase or authorisation the in-line reversals couldn't undo).
    /// Errors name the failing step, never card data.
    pub async fn enqueue(&self, original: &Transaction) -> Result<(), String> {
        let (host, sent) = self.fleet.original(&original.transaction_id)
            .ok_or("no host remembers sending it, so there is nothing to reverse")?;
        let pan = ClearPan::from_digits(&original.card.pan).map_err(|e| e.to_string())?;
        let sealed = self.hsm.vault_seal(&binding(&original.transaction_id), &pan).map_err(|e| e.to_string())?;
        self.client.execute(
            "INSERT INTO pending_reversals (transaction_id, host_id, sealed_pan, card_expiry, amount_minor, currency, \
             acquirer_merchant_id, acquirer_terminal_id, original_mti, original_stan, original_transmitted) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (transaction_id) DO NOTHING",
            &[&original.transaction_id, &host, &sealed, &original.card.expiry, &(original.amount_minor as i64),
              &original.currency, &original.merchant_id, &original.terminal_id, &sent.mti, &sent.stan,
              &sent.transmitted]).await.map_err(db)?;
        Ok(())
    }

    /// PENDING, REVERSED, NOT_AT_HOST (never charged) or MANUAL (needs a person); None if never queued.
    pub async fn state(&self, transaction_id: &str) -> Result<Option<String>, String> {
        let row = self.client.query_opt("SELECT state FROM pending_reversals WHERE transaction_id = $1",
                                        &[&transaction_id]).await.map_err(db)?;
        Ok(row.map(|r| r.get(0)))
    }

    /// One pass over the owed reversals. Returns how many left the queue.
    pub async fn run_once(&self) -> Result<usize, String> {
        let rows = self.client.query(
            "SELECT transaction_id, host_id, sealed_pan, card_expiry, amount_minor, currency, acquirer_merchant_id, \
             acquirer_terminal_id, original_mti, original_stan, original_transmitted FROM pending_reversals \
             WHERE state = 'PENDING' ORDER BY created_at LIMIT 100", &[]).await.map_err(db)?;
        let mut done = 0;
        for row in rows {
            let id: String = row.get(0);
            let host: String = row.get(1);
            let (state, code) = self.resend(&row, &id, &host).await;
            if state != "PENDING" {
                done += 1;
            }
            self.client.execute(
                "UPDATE pending_reversals SET state = $2::varchar, \
                 response_code = coalesce($3::varchar, response_code), \
                 sealed_pan = CASE WHEN $2::varchar = 'PENDING' THEN sealed_pan END, attempts = attempts + 1, \
                 updated_at = now() WHERE transaction_id = $1", &[&id, &state, &code]).await.map_err(db)?;
        }
        Ok(done)
    }

    async fn resend(&self, row: &tokio_postgres::Row, id: &str, host: &str) -> (&'static str, Option<String>) {
        let original = Original { mti: row.get(8), stan: row.get(9), transmitted: row.get(10) };
        if !self.fleet.restore_original(host, id, original) {
            eprintln!("reversal of {id}: host {host} is no longer configured; needs a person");
            return ("MANUAL", None);
        }
        let pan = match self.hsm.vault_open(&binding(id), row.get(2)) {
            Ok(pan) => pan,
            Err(e) => {
                eprintln!("reversal of {id}: queued card data won't open ({e}); needs a person");
                return ("MANUAL", None);
            }
        };
        let mut reversal = Transaction {
            transaction_id: format!("{id}-rev"),
            kind: TransactionKind::Reversal { original_transaction_id: id.to_owned() },
            amount_minor: row.get::<_, i64>(4) as u64,
            currency: row.get(5),
            merchant_id: row.get(6),
            terminal_id: row.get(7),
            card: Card { pan: pan.as_str().to_owned(), expiry: row.get(3), icc: None },
        };
        let mut ctx = RequestContext::with_timeout(self.timeout, id);
        ctx.host_hint = vec![host.to_owned()]; // only the host holding the original can undo it
        let result = self.fleet.send_transaction(&ctx, &reversal).await;
        zeroize::Zeroize::zeroize(&mut reversal.card.pan);
        match result {
            Ok(resp) if matches!(resp.decision, Decision::Approved { .. }) => ("REVERSED", Some(resp.response_code)),
            Ok(resp) if resp.response_code == UNABLE_TO_LOCATE_ORIGINAL => ("NOT_AT_HOST", Some(resp.response_code)),
            Ok(resp) => ("MANUAL", Some(resp.response_code)),
            Err(_) => ("PENDING", None), // not delivered or no answer: try again next pass
        }
    }

    /// Runs forever, one pass every `every`.
    pub async fn run(self: Arc<Self>, every: Duration) {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            match self.run_once().await {
                Ok(0) => {}
                Ok(n) => eprintln!("reversal queue: {n} reversal(s) resolved"),
                Err(e) => eprintln!("reversal queue pass failed: {e}"),
            }
        }
    }
}
