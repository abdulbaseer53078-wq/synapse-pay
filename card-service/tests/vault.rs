//! Step 29 gate: a saved card becomes a token, the vault holds nothing a thief could read, and only this
//! service, for the merchant that saved it, can pay with it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use card_service::fleet::Fleet;
use card_service::flow::{CardFlow, CardRequest, FlowError, Kind, Timeouts};
use card_service::hsm::{ClearPan, SimHsm};
use card_service::http::AppState;
use card_service::vault::{MemoryStore, NoNetworkTokens, SimulatedTokenService, TokenType, TokenizeRequest, Vault,
                          VaultError, VaultStore};
use card_service::vault_pg::PgStore;
use host_connector::mock::MockHostConnector;
use host_connector::unified::Status;
use http_body_util::BodyExt;
use sha2::Digest;
use tower::ServiceExt;

const BDK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const VISA: &str = "4111111111111111";
const RUPAY: &str = "6070000000000002";

fn hsm() -> Arc<SimHsm> {
    Arc::new(SimHsm::from_hex(BDK).unwrap())
}

fn vault(store: Arc<dyn VaultStore>, dpans: bool) -> Vault {
    Vault {
        store,
        hsm: hsm(),
        network_tokens: if dpans { Arc::new(SimulatedTokenService::default()) } else { Arc::new(NoNetworkTokens) },
    }
}

fn save<'a>(merchant: &'a str, pan: &str, network: &'a str, expiry: &'a str) -> TokenizeRequest<'a> {
    TokenizeRequest { merchant_id: merchant, pan: ClearPan::from_digits(pan).unwrap(), card_network: network,
                      card_expiry: expiry, customer_ref: Some("cust_42") }
}

/// Every 13–19 digit run that passes the Luhn check: what a PCI scan looks for in data at rest.
fn card_numbers(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for run in text.split(|c: char| !c.is_ascii_digit()).filter(|r| r.len() >= 13) {
        for len in 13..=19.min(run.len()) {
            for start in 0..=run.len() - len {
                let candidate = &run[start..start + len];
                if ClearPan::from_digits(candidate).is_ok() {
                    found.push(candidate.to_owned());
                }
            }
        }
    }
    found
}

#[tokio::test]
async fn the_same_card_gets_the_same_token_per_merchant_only() {
    let v = vault(Arc::new(MemoryStore::default()), false);
    let first = v.tokenize(save("m_1", VISA, "VISA", "08/28")).await.unwrap();
    assert!(first.token.starts_with("tok_") && first.token.len() == 36);
    assert_eq!((first.card_bin.as_str(), first.card_last4.as_str(), first.token_type), ("411111", "1111", TokenType::Pan));

    let again = v.tokenize(save("m_1", VISA, "VISA", "09/30")).await.unwrap();
    assert_eq!(again.token, first.token, "a card saved twice is one token");
    assert_eq!(v.resolve("m_1", &first.token).await.unwrap().1, "09/30", "with the newer expiry");

    let elsewhere = v.tokenize(save("m_2", VISA, "VISA", "08/28")).await.unwrap();
    assert_ne!(elsewhere.token, first.token, "another merchant can't learn the card was seen before");
}

#[tokio::test]
async fn only_the_merchant_that_saved_it_can_use_a_live_token() {
    let v = vault(Arc::new(MemoryStore::default()), false);
    let t = v.tokenize(save("m_1", VISA, "VISA", "08/28")).await.unwrap();
    assert_eq!(v.resolve("m_1", &t.token).await.unwrap().0.as_str(), VISA);
    assert_eq!(v.resolve("m_2", &t.token).await.unwrap_err(), VaultError::UnknownToken);
    assert_eq!(v.revoke("m_2", &t.token).await.unwrap_err(), VaultError::UnknownToken, "nor revoke it");

    v.revoke("m_1", &t.token).await.unwrap();
    assert_eq!(v.resolve("m_1", &t.token).await.unwrap_err(), VaultError::UnknownToken, "revoked at once");
    let index = v.index("m_1").await.unwrap();
    assert_eq!(index.len(), 1);
    assert!(index[0].revoked, "the index keeps revoked tokens, so an edge node's copy drops them");
    let fresh = v.tokenize(save("m_1", VISA, "VISA", "08/28")).await.unwrap();
    assert_ne!(fresh.token, t.token, "saving it again after revocation gives a new token");
}

#[tokio::test]
async fn a_tampered_or_swapped_ciphertext_does_not_decrypt() {
    let store = Arc::new(MemoryStore::default());
    let v = vault(store.clone(), false);
    let a = v.tokenize(save("m_1", VISA, "VISA", "08/28")).await.unwrap();
    let b = v.tokenize(save("m_1", RUPAY, "RUPAY", "08/28")).await.unwrap();
    let rows = store.dump();
    let sealed = |t: &str| rows.iter().find(|r| r.token == t).unwrap().sealed.clone();

    // B's ciphertext moved into A's row: it is bound to B's token, so it no longer opens.
    store.set_sealed(&a.token, sealed(&b.token));
    assert!(matches!(v.resolve("m_1", &a.token).await, Err(VaultError::BadCardData(_))));
    let mut edited = sealed(&b.token);
    edited.replace_range(10..11, if &edited[10..11] == "A" { "B" } else { "A" });
    store.set_sealed(&b.token, edited);
    assert!(matches!(v.resolve("m_1", &b.token).await, Err(VaultError::BadCardData(_))));
}

#[tokio::test]
async fn nothing_at_rest_is_a_readable_card_number() {
    let store = Arc::new(MemoryStore::default());
    let v = vault(store.clone(), true);
    for (pan, network) in [(VISA, "VISA"), (RUPAY, "RUPAY"), ("5555555555554444", "MASTERCARD")] {
        v.tokenize(save("m_1", pan, network, "08/28")).await.unwrap();
    }
    for row in store.dump() {
        let at_rest = format!("{} {} {} {} {} {} {} {}", row.token, row.merchant_id, row.fingerprint, row.sealed,
                              row.card_bin, row.card_last4, row.card_network, row.card_expiry);
        assert!(card_numbers(&at_rest).is_empty(), "card number at rest: {at_rest}");
        // A plain SHA-256 would be reversible by trying every number in the BIN range; the fingerprint is keyed.
        for pan in [VISA, RUPAY, "5555555555554444"] {
            let plain: String = sha2::Sha256::digest(pan.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
            assert_ne!(row.fingerprint, plain);
        }
        assert!(row.sealed.starts_with("sv1."));
    }
}

#[tokio::test]
async fn network_tokens_are_stored_instead_of_the_card_when_offered() {
    let store = Arc::new(MemoryStore::default());
    let v = vault(store.clone(), true);
    let visa = v.tokenize(save("m_1", VISA, "VISA", "08/28")).await.unwrap();
    assert_eq!(visa.token_type, TokenType::Dpan);
    assert_eq!((visa.card_bin.as_str(), visa.card_last4.as_str()), ("411111", "1111"), "receipts show the real card");
    let (dpan, _) = v.resolve("m_1", &visa.token).await.unwrap();
    assert_ne!(dpan.as_str(), VISA, "the vault holds the network token, not the card number");
    assert!(dpan.as_str().starts_with("489537"));

    let rupay = v.tokenize(save("m_1", RUPAY, "RUPAY", "08/28")).await.unwrap();
    assert_eq!(rupay.token_type, TokenType::Pan, "no token service for this network: the encrypted PAN is kept");
    assert_eq!(v.resolve("m_1", &rupay.token).await.unwrap().0.as_str(), RUPAY);
}

fn token_request(token: &str, merchant: Option<&str>) -> CardRequest {
    CardRequest {
        transaction_id: "txn_tok".into(), kind: Kind::Purchase, amount: 50_000, currency: "INR".into(),
        acquirer_terminal_id: "TERM0001".into(), acquirer_merchant_id: "MERCHANT0000001".into(),
        encrypted_card_data: String::new(), card_expiry: String::new(), pin_block: None, emv_data: None,
        host_hint: Vec::new(), trace_id: None, card_token: Some(token.into()), merchant_id: merchant.map(Into::into),
    }
}

#[tokio::test]
async fn a_returning_customer_pays_with_only_the_token() {
    let host = Arc::new(MockHostConnector::new());
    let v = Arc::new(vault(Arc::new(MemoryStore::default()), false));
    let t = v.tokenize(save("m_1", VISA, "VISA", "08/28")).await.unwrap();
    let flow = CardFlow { hsm: hsm(), host: host.clone(), timeouts: Timeouts::default(), vault: Some(v) };

    let result = flow.process(&token_request(&t.token, Some("m_1"))).await.unwrap();
    assert_eq!(result.outcome.status, Status::Captured);
    let sent = host.received();
    assert_eq!((sent[0].card.pan.as_str(), sent[0].card.expiry.as_str()), (VISA, "2808"), "the saved expiry");

    for (req, what) in [(token_request(&t.token, Some("m_2")), "another merchant"),
                        (token_request("tok_00000000000000000000000000000000", Some("m_1")), "an unknown token")] {
        assert!(matches!(flow.process(&req).await, Err(FlowError::BadCardData(_))), "{what}");
    }
    assert!(matches!(flow.process(&token_request(&t.token, None)).await, Err(FlowError::BadRequest(_))));
    let mut both = token_request(&t.token, Some("m_1"));
    both.encrypted_card_data = "sp1.x.y".into();
    assert!(matches!(flow.process(&both).await, Err(FlowError::BadRequest(_))), "one card, not two");
    assert_eq!(host.received().len(), 1, "nothing refused reached the acquirer");
}

#[tokio::test]
async fn resolving_a_token_is_well_under_10_ms() {
    let v = vault(Arc::new(MemoryStore::default()), false);
    let t = v.tokenize(save("m_1", VISA, "VISA", "08/28")).await.unwrap();
    let start = Instant::now();
    for _ in 0..100 {
        v.resolve("m_1", &t.token).await.unwrap();
    }
    let each = start.elapsed() / 100;
    assert!(each < Duration::from_millis(10), "{each:?} per resolve");
}

#[tokio::test]
async fn http_tokenize_index_and_revoke_never_return_the_card_or_its_ciphertext() {
    let host = Arc::new(MockHostConnector::new());
    let store = Arc::new(MemoryStore::default());
    let flow = CardFlow { hsm: hsm(), host, timeouts: Timeouts::default(),
                          vault: Some(Arc::new(vault(store.clone(), false))) };
    let app = card_service::http::app(Arc::new(AppState {
        flow,
        fleet: Arc::new(Fleet::new(Default::default(), Arc::new(host_connector::stan::StanSource::single()))),
    }));
    let call = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };
    let body = serde_json::json!({"merchant_id": "m_1", "card_expiry": "08/28", "card_network": "VISA",
        "encrypted_card_data": hsm().seal([1; 10], [2; 12], "data", VISA.as_bytes())});
    let post = |b: serde_json::Value| Request::post("/card/tokens").header("content-type", "application/json")
        .body(Body::from(b.to_string())).unwrap();

    let (status, text) = call(post(body.clone())).await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    let token = serde_json::from_str::<serde_json::Value>(&text).unwrap()["token"].as_str().unwrap().to_owned();
    let (_, index) = call(Request::get("/card/tokens/index?merchant_id=m_1").body(Body::empty()).unwrap()).await;
    let sealed = store.dump()[0].sealed.clone();
    for text in [&text, &index] {
        assert!(!text.contains(VISA) && !text.contains(&sealed) && !text.contains("fingerprint"), "{text}");
    }
    assert!(index.contains(&token));

    let mut bad = body.clone();
    bad["card_network"] = "DINERS".into();
    assert_eq!(call(post(bad)).await.0, StatusCode::BAD_REQUEST);
    let mut bad = body.clone();
    bad["encrypted_card_data"] = "nope".into();
    assert_eq!(call(post(bad)).await.0, StatusCode::UNPROCESSABLE_ENTITY);

    let revoke = |m: &str| Request::delete(format!("/card/tokens/{token}?merchant_id={m}")).body(Body::empty()).unwrap();
    assert_eq!(call(revoke("m_2")).await.0, StatusCode::NOT_FOUND);
    assert_eq!(call(revoke("m_1")).await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(revoke("m_1")).await.0, StatusCode::NOT_FOUND);
}

/// The Postgres store against a real database: the dedupe index under a race, and the at-rest scan on real
/// rows. Skipped when no Postgres is reachable (set VAULT_TEST_DATABASE_URL to point at one).
#[tokio::test]
async fn postgres_store_dedupes_under_a_race_and_stores_only_ciphertext() {
    let admin = std::env::var("VAULT_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".into());
    let Ok((client, conn)) = tokio_postgres::connect(&admin, tokio_postgres::NoTls).await else {
        eprintln!("skipped: no Postgres at {admin}");
        return;
    };
    tokio::spawn(conn);
    let db = format!("synapse_vault_test_{}", std::process::id());
    client.batch_execute(&format!("DROP DATABASE IF EXISTS {db}")).await.unwrap();
    client.batch_execute(&format!("CREATE DATABASE {db}")).await.unwrap();
    let url = format!("{}/{db}", admin.rsplit_once('/').unwrap().0);

    let store: Arc<dyn VaultStore> = Arc::new(PgStore::connect(&url).await.unwrap());
    let v = Arc::new(vault(store, false));
    let saves: Vec<_> = (0..8).map(|_| {
        let v = v.clone();
        tokio::spawn(async move { v.tokenize(save("m_1", VISA, "VISA", "08/28")).await.unwrap().token })
    }).collect();
    let mut tokens = Vec::new();
    for s in saves {
        tokens.push(s.await.unwrap());
    }
    tokens.dedup();
    assert_eq!(tokens.len(), 1, "eight concurrent saves of one card: one token");

    let start = Instant::now();
    assert_eq!(v.resolve("m_1", &tokens[0]).await.unwrap().0.as_str(), VISA);
    assert!(start.elapsed() < Duration::from_millis(10), "{:?}", start.elapsed());

    let (rows_client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(conn);
    let dump: String = rows_client.query_one("SELECT string_agg(t::text, ' ') FROM token_vault t", &[]).await
        .unwrap().get(0);
    assert!(card_numbers(&dump).is_empty(), "card number at rest: {dump}");
    drop(rows_client);
    let _ = client.batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).await;
}
