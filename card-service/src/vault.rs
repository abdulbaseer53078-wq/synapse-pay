//! The token vault (Step 29): saved cards as tokens, inside the one service that may hold a card number.
//!
//! A merchant saves a card once and pays with `tok_…` afterwards. The vault keeps, per token, the card number
//! encrypted by the HSM (bound to that token) and a keyed fingerprint, so the same card saved twice by the same
//! merchant gets the same token. There is no detokenize call: a token is only ever turned back into a card number
//! inside [`crate::flow::CardFlow`], to build the authorization, and never leaves this process.
//!
//! When the card network offers a network token (Visa VTS, Mastercard MDES), the vault stores that instead of the
//! card number: it only works for this merchant, so a stolen copy is useless elsewhere. The BIN and last 4 digits
//! of the real card are kept for receipts, which PCI DSS allows.
//!
//! Tokens are per merchant: merchant B can neither use merchant A's token nor learn that A saw the same card.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::hsm::{ClearPan, Hsm, HsmError};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TokenType {
    /// The card number itself, encrypted.
    Pan,
    /// A network token from the card scheme, restricted to this merchant.
    Dpan,
}

impl TokenType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pan => "PAN",
            Self::Dpan => "DPAN",
        }
    }
}

/// One vault row. `sealed` is HSM ciphertext; nothing here is a clear card number.
#[derive(Debug, Clone)]
pub struct StoredToken {
    pub token: String,
    pub merchant_id: String,
    pub fingerprint: String,
    pub sealed: String,
    pub token_type: TokenType,
    pub card_bin: String,
    pub card_last4: String,
    pub card_network: String,
    pub card_expiry: String,
    pub customer_ref: Option<String>,
    pub revoked: bool,
}

/// What callers see: never the ciphertext.
#[derive(Debug, Clone, Serialize)]
pub struct TokenView {
    pub token: String,
    pub token_type: TokenType,
    pub card_bin: String,
    pub card_last4: String,
    pub card_network: String,
    pub card_expiry: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_ref: Option<String>,
    pub revoked: bool,
}

impl From<&StoredToken> for TokenView {
    fn from(t: &StoredToken) -> Self {
        Self {
            token: t.token.clone(), token_type: t.token_type, card_bin: t.card_bin.clone(),
            card_last4: t.card_last4.clone(), card_network: t.card_network.clone(),
            card_expiry: t.card_expiry.clone(), customer_ref: t.customer_ref.clone(), revoked: t.revoked,
        }
    }
}

#[derive(Debug)]
pub enum Inserted {
    Created,
    /// Another request saved the same card for this merchant first: use its token.
    SameCard(Box<StoredToken>),
    /// The random token already exists (astronomically rare): draw another.
    TokenTaken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Card data that can't be used (undecryptable, not a card number). Nothing was stored.
    BadCardData(String),
    BadRequest(String),
    /// No live token for this merchant. Also what another merchant's token looks like: indistinguishable on purpose.
    UnknownToken,
    Unavailable(String),
}

impl From<HsmError> for VaultError {
    fn from(e: HsmError) -> Self {
        Self::BadCardData(e.to_string())
    }
}

pub trait VaultStore: Send + Sync {
    fn find_card<'a>(&'a self, merchant_id: &'a str, fingerprint: &'a str)
        -> BoxFuture<'a, Result<Option<StoredToken>, VaultError>>;
    fn insert<'a>(&'a self, token: &'a StoredToken) -> BoxFuture<'a, Result<Inserted, VaultError>>;
    fn get<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<Option<StoredToken>, VaultError>>;
    fn update_expiry<'a>(&'a self, token: &'a str, expiry: &'a str) -> BoxFuture<'a, Result<(), VaultError>>;
    /// True if a live token was revoked.
    fn revoke<'a>(&'a self, merchant_id: &'a str, token: &'a str) -> BoxFuture<'a, Result<bool, VaultError>>;
    /// Every token of the merchant, revoked ones included, so a copy (an edge node's index) can drop them.
    fn index<'a>(&'a self, merchant_id: &'a str) -> BoxFuture<'a, Result<Vec<StoredToken>, VaultError>>;
}

/// The card scheme's token service (Visa VTS, Mastercard MDES).
pub trait NetworkTokenProvider: Send + Sync {
    /// A network token for this card, usable only by this merchant; None when the scheme offers none.
    fn provision(&self, merchant_id: &str, pan: &ClearPan, network: &str) -> Option<ClearPan>;
    /// Whether the scheme would accept this network token from this merchant.
    fn domain_ok(&self, merchant_id: &str, dpan: &ClearPan) -> bool;
}

/// No network tokens: every card is stored as its encrypted PAN.
pub struct NoNetworkTokens;

impl NetworkTokenProvider for NoNetworkTokens {
    fn provision(&self, _: &str, _: &ClearPan, _: &str) -> Option<ClearPan> {
        None
    }

    fn domain_ok(&self, _: &str, _: &ClearPan) -> bool {
        false
    }
}

/// A token service stand-in (sandbox and tests): issues Luhn-valid tokens from a token BIN range for Visa and
/// Mastercard and remembers which merchant each belongs to.
/// shortcut: no cryptogram (TAVV) per transaction; a real VTS/MDES adapter requests one for every payment.
#[derive(Default)]
pub struct SimulatedTokenService {
    issued: Mutex<HashMap<String, String>>,
}

impl NetworkTokenProvider for SimulatedTokenService {
    fn provision(&self, merchant_id: &str, _pan: &ClearPan, network: &str) -> Option<ClearPan> {
        let prefix = match network {
            "VISA" => "489537",
            "MASTERCARD" => "529999",
            _ => return None, // RuPay and Amex: no token service here, so the PAN is stored
        };
        let mut body = format!("{prefix}{:09}", rand_core::OsRng.next_u64() % 1_000_000_000);
        body.push(luhn_digit(&body));
        let dpan = ClearPan::from_digits(&body).ok()?;
        self.issued.lock().unwrap().insert(body, merchant_id.to_owned());
        Some(dpan)
    }

    fn domain_ok(&self, merchant_id: &str, dpan: &ClearPan) -> bool {
        self.issued.lock().unwrap().get(dpan.as_str()).is_some_and(|m| m == merchant_id)
    }
}

fn luhn_digit(body: &str) -> char {
    let sum: u32 = body.bytes().rev().enumerate().map(|(i, b)| {
        let d = u32::from(b - b'0');
        if i % 2 == 0 { if d * 2 > 9 { d * 2 - 9 } else { d * 2 } } else { d }
    }).sum();
    char::from(b'0' + ((10 - sum % 10) % 10) as u8)
}

pub struct TokenizeRequest<'a> {
    pub merchant_id: &'a str,
    pub pan: ClearPan,
    pub card_network: &'a str,
    pub card_expiry: &'a str,
    pub customer_ref: Option<&'a str>,
}

pub struct Vault {
    pub store: Arc<dyn VaultStore>,
    pub hsm: Arc<dyn Hsm>,
    pub network_tokens: Arc<dyn NetworkTokenProvider>,
}

fn new_token() -> String {
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    format!("tok_{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

impl Vault {
    /// Saves a card for a merchant; the same card again returns the same token (with the newer expiry).
    pub async fn tokenize(&self, req: TokenizeRequest<'_>) -> Result<TokenView, VaultError> {
        let fingerprint = self.hsm.pan_fingerprint(req.merchant_id, &req.pan)?;
        // Receipts show the real card's BIN and last 4, even when what is stored is a network token.
        let (card_bin, card_last4) = (req.pan.bin(), req.pan.last4());
        if let Some(existing) = self.store.find_card(req.merchant_id, &fingerprint).await? {
            return self.refreshed(existing, req.card_expiry).await;
        }
        let (stored_pan, token_type) = match self.network_tokens.provision(req.merchant_id, &req.pan, req.card_network) {
            Some(dpan) => (dpan, TokenType::Dpan),
            None => (req.pan, TokenType::Pan),
        };
        for _ in 0..4 {
            let token = new_token();
            let row = StoredToken {
                sealed: self.hsm.vault_seal(&token, &stored_pan)?,
                token, merchant_id: req.merchant_id.to_owned(), fingerprint: fingerprint.clone(), token_type,
                card_bin: card_bin.clone(), card_last4: card_last4.clone(), card_network: req.card_network.to_owned(),
                card_expiry: req.card_expiry.to_owned(), customer_ref: req.customer_ref.map(str::to_owned),
                revoked: false,
            };
            match self.store.insert(&row).await? {
                Inserted::Created => return Ok(TokenView::from(&row)),
                Inserted::SameCard(existing) => return self.refreshed(*existing, req.card_expiry).await,
                Inserted::TokenTaken => continue,
            }
        }
        Err(VaultError::Unavailable("could not draw an unused token".into()))
    }

    /// The card number (or network token) to authorize with, and its expiry. Inside this process only.
    pub async fn resolve(&self, merchant_id: &str, token: &str) -> Result<(ClearPan, String), VaultError> {
        let row = self.store.get(token).await?.filter(|r| r.merchant_id == merchant_id && !r.revoked)
            .ok_or(VaultError::UnknownToken)?;
        let pan = self.hsm.vault_open(token, &row.sealed)?;
        if row.token_type == TokenType::Dpan && !self.network_tokens.domain_ok(merchant_id, &pan) {
            return Err(VaultError::UnknownToken);
        }
        Ok((pan, row.card_expiry))
    }

    pub async fn revoke(&self, merchant_id: &str, token: &str) -> Result<(), VaultError> {
        if self.store.revoke(merchant_id, token).await? { Ok(()) } else { Err(VaultError::UnknownToken) }
    }

    pub async fn index(&self, merchant_id: &str) -> Result<Vec<TokenView>, VaultError> {
        Ok(self.store.index(merchant_id).await?.iter().map(TokenView::from).collect())
    }

    async fn refreshed(&self, existing: StoredToken, expiry: &str) -> Result<TokenView, VaultError> {
        if existing.card_expiry != expiry {
            self.store.update_expiry(&existing.token, expiry).await?;
        }
        Ok(TokenView { card_expiry: expiry.to_owned(), ..TokenView::from(&existing) })
    }
}

/// For tests and the sandbox without a vault database.
#[derive(Default)]
pub struct MemoryStore {
    rows: Mutex<HashMap<String, StoredToken>>,
}

impl MemoryStore {
    /// Every stored row, for the tests' "nothing readable at rest" scan.
    pub fn dump(&self) -> Vec<StoredToken> {
        self.rows.lock().unwrap().values().cloned().collect()
    }

    /// For the tamper test: overwrite a row's ciphertext.
    pub fn set_sealed(&self, token: &str, sealed: String) {
        if let Some(row) = self.rows.lock().unwrap().get_mut(token) {
            row.sealed = sealed;
        }
    }
}

impl VaultStore for MemoryStore {
    fn find_card<'a>(&'a self, merchant_id: &'a str, fingerprint: &'a str)
        -> BoxFuture<'a, Result<Option<StoredToken>, VaultError>> {
        let found = self.rows.lock().unwrap().values()
            .find(|r| r.merchant_id == merchant_id && r.fingerprint == fingerprint && !r.revoked).cloned();
        Box::pin(async move { Ok(found) })
    }

    fn insert<'a>(&'a self, token: &'a StoredToken) -> BoxFuture<'a, Result<Inserted, VaultError>> {
        let mut rows = self.rows.lock().unwrap();
        let outcome = if rows.contains_key(&token.token) {
            Inserted::TokenTaken
        } else if let Some(same) = rows.values()
            .find(|r| r.merchant_id == token.merchant_id && r.fingerprint == token.fingerprint && !r.revoked) {
            Inserted::SameCard(Box::new(same.clone()))
        } else {
            rows.insert(token.token.clone(), token.clone());
            Inserted::Created
        };
        Box::pin(async move { Ok(outcome) })
    }

    fn get<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<Option<StoredToken>, VaultError>> {
        let found = self.rows.lock().unwrap().get(token).cloned();
        Box::pin(async move { Ok(found) })
    }

    fn update_expiry<'a>(&'a self, token: &'a str, expiry: &'a str) -> BoxFuture<'a, Result<(), VaultError>> {
        if let Some(row) = self.rows.lock().unwrap().get_mut(token) {
            row.card_expiry = expiry.to_owned();
        }
        Box::pin(async move { Ok(()) })
    }

    fn revoke<'a>(&'a self, merchant_id: &'a str, token: &'a str) -> BoxFuture<'a, Result<bool, VaultError>> {
        let revoked = match self.rows.lock().unwrap().get_mut(token) {
            Some(row) if row.merchant_id == merchant_id && !row.revoked => {
                row.revoked = true;
                true
            }
            _ => false,
        };
        Box::pin(async move { Ok(revoked) })
    }

    fn index<'a>(&'a self, merchant_id: &'a str) -> BoxFuture<'a, Result<Vec<StoredToken>, VaultError>> {
        let rows = self.rows.lock().unwrap().values().filter(|r| r.merchant_id == merchant_id).cloned().collect();
        Box::pin(async move { Ok(rows) })
    }
}
