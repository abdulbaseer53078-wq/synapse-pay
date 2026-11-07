//! Task 4.7 acceptance: audit records keep the exact byte stream except sensitive values; DE 2 shows as
//! 400012******1234; no PIN block, track data or other card data is ever written.

use host_connector::audit::{mask_pan, redact, AuditSink, Direction, JsonLines};
use iso8583::{pack, Dictionary, Iso8583Message};

const PAN: &str = "4000123456781234";
const TRACK2: &str = "4000123456781234=28121011234500000";
const PIN_BLOCK: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
const EMV: [u8; 7] = [0x5A, 0x05, 0x40, 0x00, 0x12, 0x34, 0x56]; // tag 5A: the PAN again, inside chip data

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn dictionary(pan_encoding: &str) -> Dictionary {
    Dictionary::from_json(&format!(r#"{{
        "2":  {{ "type": "LLVAR", "max_length": 19, "format": "n", "encoding": "{pan_encoding}" }},
        "4":  {{ "type": "FIXED", "length": 12, "format": "n" }},
        "11": {{ "type": "FIXED", "length": 6, "format": "n" }},
        "35": {{ "type": "LLVAR", "max_length": 37, "format": "ans" }},
        "39": {{ "type": "FIXED", "length": 2, "format": "an" }},
        "41": {{ "type": "FIXED", "length": 8, "format": "ans" }},
        "48": {{ "type": "LLLVAR", "max_length": 999, "format": "ans" }},
        "52": {{ "type": "FIXED", "length": 8, "format": "b" }},
        "55": {{ "type": "LLLVAR", "max_length": 255, "format": "b" }}
    }}"#)).unwrap()
}

fn request(d: &Dictionary) -> Vec<u8> {
    let mut msg = Iso8583Message::new("0200").unwrap();
    msg.set(2, PAN.as_bytes()).unwrap();
    msg.set(4, &b"000000150000"[..]).unwrap();
    msg.set(11, &b"000123"[..]).unwrap();
    msg.set(35, TRACK2.as_bytes()).unwrap();
    msg.set(41, &b"TERM0001"[..]).unwrap();
    msg.set(48, &b"CARDHOLDER JANE DOE"[..]).unwrap(); // private field: redacted by default
    msg.set(52, &PIN_BLOCK[..]).unwrap();
    msg.set(55, &EMV[..]).unwrap();
    pack(&msg, d).unwrap()
}

/// Every secret, in every form it could take in a record: text, and hex of its wire bytes.
fn assert_no_card_data(json: &str) {
    for secret in [PAN.to_string(), hex(PAN.as_bytes()), "345678".into(), hex(b"345678"), TRACK2.into(),
                   hex(TRACK2.as_bytes()), hex(&PIN_BLOCK), hex(&EMV), "JANE DOE".into(), hex(b"JANE DOE")] {
        assert!(!json.contains(&secret), "audit record leaks {secret}: {json}");
    }
}

#[test]
fn outbound_record_masks_the_pan_and_never_contains_the_pin_block() {
    let d = dictionary("ascii");
    let raw = request(&d);
    let record = redact(&raw, &d, "txn_01JC8Z4C5D6E7F8G9H0J1K2L3M", Direction::Outbound);
    let json = serde_json::to_string(&record).unwrap();

    assert_no_card_data(&json);
    assert_eq!(record.fields[&2], "400012******1234");
    assert_eq!(record.fields[&52], "[redacted 8 bytes]");
    assert_eq!(record.fields[&35], format!("[redacted {} bytes]", TRACK2.len()));
    assert_eq!((record.fields[&4].as_str(), record.fields[&11].as_str(), record.fields[&41].as_str()),
               ("000000150000", "000123", "TERM0001"));
    assert_eq!(record.transaction_id, "txn_01JC8Z4C5D6E7F8G9H0J1K2L3M");
    assert_eq!(record.mti.as_deref(), Some("0200"));
}

#[test]
fn hex_dump_is_the_exact_byte_stream_except_redacted_values() {
    let d = dictionary("ascii");
    let raw = request(&d);
    let dump = redact(&raw, &d, "txn_1", Direction::Outbound).hex.unwrap();
    assert_eq!(dump.len(), raw.len() * 2, "one hex pair per wire byte, so offsets match the wire");
    let mut hidden = 0;
    for (i, byte) in raw.iter().enumerate() {
        match &dump[i * 2..i * 2 + 2] {
            "**" => hidden += 1,
            shown => assert_eq!(shown, format!("{byte:02X}"), "byte {i}"),
        }
    }
    // PAN, track 2, private DE 48, PIN block, chip data: values only, length prefixes kept.
    assert_eq!(hidden, PAN.len() + TRACK2.len() + 19 + PIN_BLOCK.len() + EMV.len());
    assert!(dump.starts_with(&hex(b"0200")));
    assert!(dump.contains(&format!("{}{}", hex(b"16"), "**".repeat(16))), "DE 2 length prefix kept");
}

#[test]
fn bcd_pan_is_redacted_too() {
    let d = dictionary("bcd");
    let raw = request(&d);
    let record = redact(&raw, &d, "txn_1", Direction::Outbound);
    assert_eq!(record.fields[&2], "400012******1234");
    assert!(!record.hex.unwrap().contains("4000123456781234"), "packed BCD PAN reads as its digits in hex");
}

#[test]
fn inbound_response_is_redacted_the_same_way() {
    let d = dictionary("ascii");
    let mut msg = Iso8583Message::new("0210").unwrap();
    msg.set(2, PAN.as_bytes()).unwrap();
    msg.set(11, &b"000123"[..]).unwrap();
    msg.set(39, &b"00"[..]).unwrap();
    msg.set(55, &EMV[..]).unwrap();
    let record = redact(&pack(&msg, &d).unwrap(), &d, "txn_1", Direction::Inbound);
    assert_no_card_data(&serde_json::to_string(&record).unwrap());
    assert_eq!((record.direction, record.fields[&39].as_str()), (Direction::Inbound, "00"));
}

#[test]
fn an_unparseable_message_is_recorded_without_its_bytes() {
    let d = dictionary("ascii");
    let raw = request(&d);
    let record = redact(&raw[..raw.len() - 3], &d, "txn_1", Direction::Inbound);
    assert!(record.parse_error.is_some() && record.hex.is_none() && record.fields.is_empty());
    assert_eq!(record.length, raw.len() - 3);
    assert_no_card_data(&serde_json::to_string(&record).unwrap());
}

#[test]
fn json_lines_sink_writes_one_record_per_line() {
    let d = dictionary("ascii");
    let sink = JsonLines::new(Vec::new());
    for direction in [Direction::Outbound, Direction::Inbound] {
        sink.record(&redact(&request(&d), &d, "txn_1", direction)).unwrap();
    }
    let written = String::from_utf8(sink.into_inner()).unwrap();
    let lines: Vec<serde_json::Value> = written.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 2);
    assert_eq!((lines[0]["direction"].as_str(), lines[1]["transaction_id"].as_str()), (Some("outbound"), Some("txn_1")));
    assert_no_card_data(&written);
}

#[test]
fn pan_masking_keeps_first_6_and_last_4() {
    assert_eq!(mask_pan("4000123456781234"), "400012******1234");
    assert_eq!(mask_pan("6521000000000000001"), "652100*********0001");
    assert_eq!(mask_pan("123456789012"), "************", "too short to show 10 digits safely");
}
