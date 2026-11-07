//! Property tests for the gate's "a parser must never panic": random and mutated messages, against every
//! dialect, must produce Ok or Err, never a panic. Anything unpack accepts must also round-trip exactly.

use std::fs;
use std::path::Path;

use iso8583::{pack, unpack, Dictionary, Iso8583Message};
use proptest::prelude::*;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every shipped dialect, plus the synthetic host re-framed with a BCD MTI and hex bitmaps.
fn dialects() -> Vec<Dictionary> {
    let mut out: Vec<Dictionary> = fs::read_dir(root().join("dialects")).unwrap()
        .map(|e| Dictionary::from_json(&fs::read_to_string(e.unwrap().path()).unwrap()).unwrap())
        .collect();
    let synthetic = fs::read_to_string(root().join("dialects/synthetic-host.json")).unwrap();
    let reframed = synthetic.replacen('{', r#"{ "mti": "bcd", "bitmap": "hex","#, 1);
    out.push(Dictionary::from_json(&reframed).unwrap());
    out
}

/// Valid wire messages to mutate: the host fixtures.
fn seeds() -> Vec<Vec<u8>> {
    fs::read_dir(root().join("tests/fixtures")).unwrap().map(|e| {
        let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(e.unwrap().path()).unwrap()).unwrap();
        let hex = json["hex"].as_str().unwrap();
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }).collect()
}

#[derive(Debug, Clone)]
enum Edit {
    Flip(usize, u8),
    Truncate(usize),
    Insert(usize, u8),
    Remove(usize),
}

fn apply(mut wire: Vec<u8>, edits: &[Edit]) -> Vec<u8> {
    for edit in edits {
        let len = wire.len().max(1);
        match *edit {
            Edit::Flip(i, mask) => if !wire.is_empty() { wire[i % len] ^= mask },
            Edit::Truncate(i) => wire.truncate(i % len),
            Edit::Insert(i, b) => wire.insert(i % (wire.len() + 1), b),
            Edit::Remove(i) => if !wire.is_empty() { wire.remove(i % len); },
        }
    }
    wire
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (any::<usize>(), 1..=u8::MAX).prop_map(|(i, m)| Edit::Flip(i, m)),
        any::<usize>().prop_map(Edit::Truncate),
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Edit::Insert(i, b)),
        any::<usize>().prop_map(Edit::Remove),
    ]
}

/// Anything unpack accepts must pack back to exactly the same bytes.
fn check(wire: &[u8], d: &Dictionary) -> Result<(), TestCaseError> {
    if let Ok(msg) = unpack(wire, d) {
        let repacked = pack(&msg, d).map_err(|e| TestCaseError::fail(format!("accepted but can't pack: {e}")))?;
        prop_assert!(repacked == wire, "accepted message doesn't round-trip");
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn random_bytes_never_panic(wire in proptest::collection::vec(any::<u8>(), 0..400)) {
        for d in dialects() {
            check(&wire, &d)?;
        }
    }

    #[test]
    fn mutated_real_shaped_messages_never_panic(seed in any::<prop::sample::Index>(),
                                                edits in proptest::collection::vec(edit(), 1..6)) {
        let seeds = seeds();
        let wire = apply(seeds[seed.index(seeds.len())].clone(), &edits);
        for d in dialects() {
            check(&wire, &d)?;
        }
    }

    #[test]
    fn building_arbitrary_messages_never_panics(
        mti in "[0-9]{4}",
        fields in proptest::collection::vec((any::<u8>(), proptest::collection::vec(any::<u8>(), 0..40)), 0..12),
    ) {
        for d in dialects() {
            let mut msg = Iso8583Message::new(&mti).unwrap();
            for (n, value) in &fields {
                let _ = msg.set(*n, value.as_slice());
            }
            if let Ok(wire) = pack(&msg, &d) {
                let back = unpack(&wire, &d).map_err(|e| TestCaseError::fail(format!("packed but can't unpack: {e}")))?;
                prop_assert_eq!(back.fields().collect::<Vec<_>>(), msg.fields().collect::<Vec<_>>());
            }
        }
    }
}
