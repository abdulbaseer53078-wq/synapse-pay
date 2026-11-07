//! Task 3.7: host message suite. Every file in tests/fixtures/ is one message: its hex dump, the dialect to
//! read it with, and the exact field values it must contain. Each is checked three ways:
//!   1. parse the dump  → MTI and every field exactly as expected, and no other fields;
//!   2. build from the expected fields → exactly the dump;
//!   3. round trip: pack(unpack(dump)) == dump.
//!
//! Fixture format (binary fields as {"hex": ...}):
//!   { "synthetic": false, "description": "...", "dialect": "<file in dialects/>",
//!     "hex": "3031303072...", "mti": "0100", "fields": { "2": "4111...", "55": {"hex": "9F26..."} } }
//!
//! The current fixtures are SYNTHETIC (generated independently of this crate). Replace them with sanitized
//! acquirer dumps: test card numbers only, PIN blocks and track data zeroed. Never commit a real PAN.
//! `cargo test -- --ignored` runs the acceptance gate, which fails until 10 real messages are present.

use std::fs;
use std::path::{Path, PathBuf};

use iso8583::{pack, unpack, Dictionary, Iso8583Message};
use serde_json::Value;

const MIN_MESSAGE_TYPES: usize = 10;

struct Fixture {
    name: String,
    synthetic: bool,
    dialect: Dictionary,
    wire: Vec<u8>,
    mti: String,
    fields: Vec<(u8, Vec<u8>)>, // ascending
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit")).collect()
}

fn fixtures() -> Vec<Fixture> {
    let mut paths: Vec<_> = fs::read_dir(root().join("tests/fixtures")).unwrap()
        .map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
    paths.sort();
    paths.into_iter().map(|path| {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let json: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let dialect_file = root().join("dialects").join(json["dialect"].as_str().unwrap());
        let mut fields: Vec<(u8, Vec<u8>)> = json["fields"].as_object().unwrap().iter().map(|(k, v)| {
            let value = match v {
                Value::String(s) => s.as_bytes().to_vec(),
                _ => unhex(v["hex"].as_str().unwrap_or_else(|| panic!("{name}: DE {k} must be text or {{\"hex\"}}"))),
            };
            (k.parse().unwrap(), value)
        }).collect();
        fields.sort();
        Fixture {
            synthetic: json["synthetic"].as_bool().unwrap_or_else(|| panic!("{name}: \"synthetic\" must be set")),
            dialect: Dictionary::from_json(&fs::read_to_string(dialect_file).unwrap()).unwrap(),
            wire: unhex(json["hex"].as_str().unwrap()),
            mti: json["mti"].as_str().unwrap().to_owned(),
            fields,
            name,
        }
    }).collect()
}

#[test]
fn every_dump_parses_to_exactly_the_expected_fields() {
    for f in fixtures() {
        let msg = unpack(&f.wire, &f.dialect).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert_eq!(msg.mti(), f.mti, "{}", f.name);
        let actual: Vec<(u8, Vec<u8>)> = msg.fields().map(|n| (n, msg.get(n).unwrap().to_vec())).collect();
        // Compare numbers first, then values per field, so a failure names the field but never prints a PAN.
        assert_eq!(actual.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
                   f.fields.iter().map(|(n, _)| *n).collect::<Vec<_>>(), "{}: field set", f.name);
        for ((n, got), (_, want)) in actual.iter().zip(&f.fields) {
            assert!(got == want, "{}: DE {n} differs", f.name);
        }
    }
}

#[test]
fn building_from_fields_reproduces_every_dump() {
    for f in fixtures() {
        let mut msg = Iso8583Message::new(&f.mti).unwrap();
        for (n, value) in &f.fields {
            msg.set(*n, value.as_slice()).unwrap();
        }
        let built = pack(&msg, &f.dialect).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert!(built == f.wire, "{}: built bytes differ from the dump", f.name);
    }
}

#[test]
fn every_dump_round_trips() {
    for f in fixtures() {
        let repacked = pack(&unpack(&f.wire, &f.dialect).unwrap(), &f.dialect).unwrap();
        assert!(repacked == f.wire, "{}: pack(unpack(dump)) != dump", f.name);
    }
}

#[test]
fn the_suite_covers_at_least_ten_message_types() {
    let mut mtis: Vec<String> = fixtures().into_iter().map(|f| f.mti).collect();
    mtis.dedup();
    assert!(mtis.len() >= MIN_MESSAGE_TYPES, "only {} message types: {mtis:?}", mtis.len());
}

/// Task 3.7 acceptance: fails until 10 distinct message types come from real (sanitized) acquirer dumps.
#[test]
#[ignore = "needs sanitized acquirer dumps; run with --ignored for sign-off"]
fn acceptance_ten_real_acquirer_messages() {
    let mut real: Vec<String> = fixtures().into_iter().filter(|f| !f.synthetic).map(|f| f.mti).collect();
    real.dedup();
    assert!(real.len() >= MIN_MESSAGE_TYPES,
            "{} real message types; the rest are synthetic placeholders", real.len());
}
