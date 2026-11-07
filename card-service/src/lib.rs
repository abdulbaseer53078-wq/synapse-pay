//! Card transaction service (Stage 1, Step 5).
//!
//! The API backend never sees a card number: it forwards the terminal's encrypted card data here, this
//! service decrypts it in the HSM ([`hsm`]), sends it to the acquirer through the host connector, reverses it
//! if the outcome is unknown ([`flow`]), and answers with the outcome and a masked card.

pub mod flow;
pub mod hsm;
pub mod http;
