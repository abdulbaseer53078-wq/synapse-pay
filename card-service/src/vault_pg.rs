//! The vault's own Postgres database (Step 29), separate from the platform's: only this service has its
//! credentials, so a breach of the API database exposes no vault rows at all, and the rows themselves hold only HSM
//! ciphertext and keyed fingerprints.

use std::sync::Arc;

use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, NoTls, Row};

use crate::vault::{BoxFuture, Inserted, StoredToken, TokenType, VaultError, VaultStore};

pub const MIGRATION: &str = include_str!("../migrations/001_token_vault.sql");

const COLUMNS: &str = "token, merchant_id, pan_fingerprint, encrypted_pan, token_type, card_bin, card_last4, \
                       card_network, card_expiry, customer_ref, revoked_at IS NOT NULL";

pub struct PgStore {
    client: Arc<Client>,
}

impl PgStore {
    /// Connects, applies the vault's migration (idempotent) and keeps the connection driven in the background.
    /// shortcut: one pipelined connection, no TLS (the vault database sits beside this service in its private
    /// subnet); use a pool and TLS (verify-full) once it runs on RDS.
    pub async fn connect(url: &str) -> Result<Self, String> {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("vault database connection closed: {e}");
            }
        });
        client.batch_execute(MIGRATION).await.map_err(|e| e.to_string())?;
        Ok(Self { client: Arc::new(client) })
    }
}

fn unavailable(e: tokio_postgres::Error) -> VaultError {
    // The driver's message names the failing statement at most, never parameter values.
    VaultError::Unavailable(format!("vault database: {e}"))
}

fn row(r: &Row) -> StoredToken {
    StoredToken {
        token: r.get(0), merchant_id: r.get(1), fingerprint: r.get(2), sealed: r.get(3),
        token_type: if r.get::<_, &str>(4) == "DPAN" { TokenType::Dpan } else { TokenType::Pan },
        card_bin: r.get(5), card_last4: r.get(6), card_network: r.get(7), card_expiry: r.get(8),
        customer_ref: r.get(9), revoked: r.get(10),
    }
}

impl VaultStore for PgStore {
    fn find_card<'a>(&'a self, merchant_id: &'a str, fingerprint: &'a str)
        -> BoxFuture<'a, Result<Option<StoredToken>, VaultError>> {
        Box::pin(async move {
            let rows = self.client.query(
                &format!("SELECT {COLUMNS} FROM token_vault WHERE merchant_id = $1 AND pan_fingerprint = $2 \
                          AND revoked_at IS NULL"), &[&merchant_id, &fingerprint]).await.map_err(unavailable)?;
            Ok(rows.first().map(row))
        })
    }

    fn insert<'a>(&'a self, t: &'a StoredToken) -> BoxFuture<'a, Result<Inserted, VaultError>> {
        Box::pin(async move {
            let kind = t.token_type.as_str();
            let result = self.client.execute(
                "INSERT INTO token_vault (token, merchant_id, pan_fingerprint, encrypted_pan, token_type, card_bin, \
                 card_last4, card_network, card_expiry, customer_ref) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[&t.token, &t.merchant_id, &t.fingerprint, &t.sealed, &kind, &t.card_bin, &t.card_last4,
                  &t.card_network, &t.card_expiry, &t.customer_ref]).await;
            match result {
                Ok(_) => Ok(Inserted::Created),
                Err(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
                    // Which constraint: the token's primary key, or the one-live-token-per-card index.
                    if let Some(same) = self.find_card(&t.merchant_id, &t.fingerprint).await? {
                        Ok(Inserted::SameCard(Box::new(same)))
                    } else {
                        Ok(Inserted::TokenTaken)
                    }
                }
                Err(e) => Err(unavailable(e)),
            }
        })
    }

    fn get<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<Option<StoredToken>, VaultError>> {
        Box::pin(async move {
            let rows = self.client.query(&format!("SELECT {COLUMNS} FROM token_vault WHERE token = $1"), &[&token])
                .await.map_err(unavailable)?;
            Ok(rows.first().map(row))
        })
    }

    fn update_expiry<'a>(&'a self, token: &'a str, expiry: &'a str) -> BoxFuture<'a, Result<(), VaultError>> {
        Box::pin(async move {
            self.client.execute("UPDATE token_vault SET card_expiry = $2, updated_at = now() WHERE token = $1",
                                &[&token, &expiry]).await.map_err(unavailable)?;
            Ok(())
        })
    }

    fn revoke<'a>(&'a self, merchant_id: &'a str, token: &'a str) -> BoxFuture<'a, Result<bool, VaultError>> {
        Box::pin(async move {
            let n = self.client.execute(
                "UPDATE token_vault SET revoked_at = now(), updated_at = now() \
                 WHERE token = $1 AND merchant_id = $2 AND revoked_at IS NULL", &[&token, &merchant_id])
                .await.map_err(unavailable)?;
            Ok(n == 1)
        })
    }

    fn index<'a>(&'a self, merchant_id: &'a str) -> BoxFuture<'a, Result<Vec<StoredToken>, VaultError>> {
        Box::pin(async move {
            let rows = self.client.query(
                &format!("SELECT {COLUMNS} FROM token_vault WHERE merchant_id = $1 ORDER BY created_at, token"),
                &[&merchant_id]).await.map_err(unavailable)?;
            Ok(rows.iter().map(row).collect())
        })
    }
}
