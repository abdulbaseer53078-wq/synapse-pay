//! Card transaction service (Stage 1, Step 5).
//!
//! The API backend never sees a card number: it forwards the terminal's encrypted card data here, this
//! service decrypts it in the HSM ([`hsm`]), sends it to the acquirer through the host connector, reverses it
//! if the outcome is unknown ([`flow`]), and answers with the outcome and a masked card. Saved cards are tokens in
//! the [`vault`], which only this service can turn back into a card number.

pub mod fleet;
pub mod flow;
pub mod hsm;
pub mod http;
pub mod vault;
pub mod vault_pg;
