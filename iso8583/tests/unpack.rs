//! Task 3.4 acceptance: unpacking sample messages against host dictionaries.
//!
//! The RuPay and Visa dialects and samples are ILLUSTRATIVE: built from public ISO 8583 conventions
//! (ASCII vs packed BCD), not from the networks' confidential specs. Replace them with the acquirer's
//! certification test vectors before going live. Bitmaps below are worked out by hand, not by the builder.

use iso8583::{pack, unpack, BitmapError, Dictionary, FieldError, Iso8583Message, PackError, ParseError};

fn dictionary(json: &str) -> Dictionary {
    Dictionary::from_json(json).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// RuPay-style 0100 authorization request: ASCII fields and prefixes, primary + secondary bitmap.
fn rupay_auth_request() -> Vec<u8> {
    [
        b"0100".to_vec(),
        // Primary: bits 1(secondary) 2 3 4 7 | 11-14 | 18 22 | 25 32 | 37 | 41 42 48 | 49 | -
        hex("F2 3C 44 81 08 C1 80 00"),
        // Secondary: bit 102.
        hex("00 00 00 00 04 00 00 00"),
        b"16".to_vec(), b"6521000000000001".to_vec(), // DE 2   PAN (LLVAR), synthetic
        b"000000".to_vec(),                         // DE 3   processing code: purchase
        b"000000150000".to_vec(),                   // DE 4   amount: 1500.00
        b"1107101530".to_vec(),                     // DE 7   transmission date/time MMDDhhmmss
        b"123456".to_vec(),                         // DE 11  STAN
        b"101530".to_vec(),                         // DE 12  local time
        b"1107".to_vec(),                           // DE 13  local date
        b"2812".to_vec(),                           // DE 14  expiry YYMM
        b"5411".to_vec(),                           // DE 18  MCC: grocery
        b"051".to_vec(),                            // DE 22  POS entry: chip
        b"00".to_vec(),                             // DE 25  POS condition
        b"06".to_vec(), b"123456".to_vec(),         // DE 32  acquirer institution (LLVAR)
        b"531110123456".to_vec(),                   // DE 37  RRN
        b"TERM0001".to_vec(),                       // DE 41  terminal id
        b"MERCHANT0000001".to_vec(),                // DE 42  merchant id
        b"011".to_vec(), b"SYNAPSEPAY1".to_vec(),   // DE 48  private data (LLLVAR)
        b"356".to_vec(),                            // DE 49  currency: INR
        b"10".to_vec(), b"1234567890".to_vec(),     // DE 102 account id (LLVAR)
    ]
    .concat()
}

/// Visa-style 0110 authorization response: packed BCD numerics and prefixes, ASCII text, binary EMV data.
fn visa_auth_response() -> Vec<u8> {
    [
        b"0110".to_vec(),
        // Primary only: bits 2 3 4 7 | 11 | - | - | 37 38 39 | 41 | 49 55 | -
        hex("72 20 00 00 0E 80 82 00"),
        hex("16 41 11 11 11 11 11 11 11"),    // DE 2   LL=0x16, PAN 4111111111111111 in 8 BCD bytes
        hex("00 00 00"),                      // DE 3   000000
        hex("00 00 00 15 00 00"),             // DE 4   000000150000
        hex("11 07 10 15 31"),                // DE 7   1107101531
        hex("12 34 56"),                      // DE 11  123456
        b"531110123456".to_vec(),             // DE 37  RRN
        b"A1B2C3".to_vec(),                   // DE 38  auth code
        b"00".to_vec(),                       // DE 39  response: approved
        b"TERM0001".to_vec(),                 // DE 41
        hex("08 40"),                         // DE 49  840 (odd: 0 pad nibble)
        hex("00 07  91 05 01 02 03 04 05"),   // DE 55  LLL=0x0007, EMV tag 91 (issuer auth data)
    ]
    .concat()
}

#[test]
fn parses_a_rupay_authorization_request() {
    let d = dictionary(include_str!("../dialects/illustrative-rupay.json"));
    let wire = rupay_auth_request();
    let msg = unpack(&wire, &d).unwrap();

    assert_eq!(msg.mti(), "0100");
    assert_eq!(msg.fields().collect::<Vec<_>>(),
               [2, 3, 4, 7, 11, 12, 13, 14, 18, 22, 25, 32, 37, 41, 42, 48, 49, 102]);
    for (field, value) in [(2, "6521000000000001"), (3, "000000"), (4, "000000150000"), (7, "1107101530"),
                           (22, "051"), (32, "123456"), (37, "531110123456"), (41, "TERM0001"),
                           (42, "MERCHANT0000001"), (48, "SYNAPSEPAY1"), (49, "356"), (102, "1234567890")] {
        assert_eq!(msg.get_str(field), Some(value), "DE {field}");
    }
    assert_eq!(msg.get(39), None);
    // ASCII values are borrowed from the input buffer, not copied.
    assert!(wire.as_ptr_range().contains(&msg.get(42).unwrap().as_ptr()));
}

#[test]
fn parses_a_visa_authorization_response() {
    let d = dictionary(include_str!("../dialects/illustrative-visa.json"));
    let wire = visa_auth_response();
    let msg = unpack(&wire, &d).unwrap();

    assert_eq!(msg.mti(), "0110");
    assert_eq!(msg.fields().collect::<Vec<_>>(), [2, 3, 4, 7, 11, 37, 38, 39, 41, 49, 55]);
    for (field, value) in [(2, "4111111111111111"), (3, "000000"), (4, "000000150000"), (7, "1107101531"),
                           (11, "123456"), (37, "531110123456"), (38, "A1B2C3"), (39, "00"), (41, "TERM0001"),
                           (49, "840")] {
        assert_eq!(msg.get_str(field), Some(value), "DE {field}");
    }
    assert_eq!(msg.get(55), Some(&hex("91 05 01 02 03 04 05")[..]), "binary stays raw");
}

#[test]
fn handles_secondary_and_tertiary_bitmaps() {
    let d = dictionary(r#"{
        "3": { "type": "FIXED", "length": 6, "format": "n" },
        "70": { "type": "FIXED", "length": 3, "format": "n" },
        "130": { "type": "LLVAR", "max_length": 20, "format": "ans" }
    }"#);
    let wire = [
        b"0800".to_vec(),
        hex("A0 00 00 00 00 00 00 00"), // bits 1 (secondary follows) and 3
        hex("84 00 00 00 00 00 00 00"), // bits 65 (tertiary follows) and 70
        hex("40 00 00 00 00 00 00 00"), // bit 130
        b"990000".to_vec(),             // DE 3
        b"301".to_vec(),                // DE 70: echo test
        b"05".to_vec(), b"HELLO".to_vec(), // DE 130
    ]
    .concat();
    let msg = unpack(&wire, &d).unwrap();
    assert_eq!(msg.fields().collect::<Vec<_>>(), [3, 70, 130]);
    assert_eq!((msg.get_str(3), msg.get_str(70), msg.get_str(130)), (Some("990000"), Some("301"), Some("HELLO")));
}

#[test]
fn misaligned_messages_fail_instead_of_guessing() {
    let rupay = dictionary(include_str!("../dialects/illustrative-rupay.json"));
    let wire = rupay_auth_request();

    let mut trailing = wire.clone();
    trailing.push(b'X');
    assert_eq!(unpack(&trailing, &rupay).unwrap_err(), ParseError::TrailingBytes(1));

    let truncated = &wire[..wire.len() - 3];
    assert!(matches!(unpack(truncated, &rupay), Err(ParseError::Field(FieldError::Truncated { field: 102, .. }))));

    let mut unknown = wire.clone();
    unknown[4] |= 0x08; // set bit 5: DE 5 isn't in the dictionary
    assert_eq!(unpack(&unknown, &rupay).unwrap_err(), ParseError::Field(FieldError::Undefined(5)));

    assert_eq!(unpack(b"01X0", &rupay).unwrap_err(), ParseError::InvalidMti);
    assert_eq!(unpack(b"01", &rupay).unwrap_err(), ParseError::InvalidMti);
}

#[test]
fn debug_output_never_shows_card_numbers() {
    let d = dictionary(include_str!("../dialects/illustrative-visa.json"));
    let wire = visa_auth_response();
    let shown = format!("{:?}", unpack(&wire, &d).unwrap());
    assert!(!shown.contains("4111"), "{shown}");
    assert!(shown.contains("(2, 16)"), "{shown}"); // field number and length only
}

// Task 3.5 acceptance: pack is the exact inverse of unpack, and enforces the dialect's required fields.

#[test]
fn pack_unpack_round_trips_byte_for_byte() {
    let tertiary = r#"{
        "3": { "type": "FIXED", "length": 6, "format": "n" },
        "70": { "type": "FIXED", "length": 3, "format": "n" },
        "130": { "type": "LLVAR", "max_length": 20, "format": "ans" }
    }"#;
    let tertiary_wire = [b"0800".to_vec(), hex("A0 00 00 00 00 00 00 00 84 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00"),
                         b"99000030105HELLO".to_vec()].concat();
    for (name, d, wire) in [
        ("rupay ascii", dictionary(include_str!("../dialects/illustrative-rupay.json")), rupay_auth_request()),
        ("visa bcd", dictionary(include_str!("../dialects/illustrative-visa.json")), visa_auth_response()),
        ("tertiary bitmap", dictionary(tertiary), tertiary_wire),
    ] {
        let repacked = pack(&unpack(&wire, &d).unwrap(), &d).unwrap();
        assert_eq!(repacked, wire, "{name}");
    }
}

#[test]
fn builds_a_message_from_scratch() {
    let d = dictionary(include_str!("../dialects/illustrative-visa.json"));
    let mut msg = Iso8583Message::new("0110").unwrap();
    // Set out of order: pack still writes fields ascending, with a bitmap generated from what's present.
    for (field, value) in [(49, "840"), (2, "4111111111111111"), (39, "00"), (4, "000000150000"),
                           (3, "000000"), (41, "TERM0001"), (7, "1107101531"), (37, "531110123456"),
                           (11, "123456"), (38, "A1B2C3")] {
        msg.set(field, value.as_bytes()).unwrap();
    }
    msg.set(55, hex("91 05 01 02 03 04 05")).unwrap();
    assert_eq!(pack(&msg, &d).unwrap(), visa_auth_response());
}

#[test]
fn missing_required_field_is_an_error() {
    let d = dictionary(r#"{
        "2": { "type": "LLVAR", "max_length": 19, "format": "n" },
        "4": { "type": "FIXED", "length": 12, "format": "n" },
        "39": { "type": "FIXED", "length": 2, "format": "an" },
        "required": { "0100": [2, 4], "0110": [39] }
    }"#);
    let mut request = Iso8583Message::new("0100").unwrap();
    request.set(2, &b"4111111111111111"[..]).unwrap();
    assert_eq!(pack(&request, &d), Err(PackError::MissingField(4)));
    request.set(4, &b"000000150000"[..]).unwrap();
    assert!(pack(&request, &d).is_ok());

    let response = Iso8583Message::new("0110").unwrap();
    assert_eq!(pack(&response, &d), Err(PackError::MissingField(39)));
    // An MTI the dialect sets no rule for has no required fields.
    assert!(pack(&Iso8583Message::new("0800").unwrap(), &d).is_ok());
}

#[test]
fn invalid_values_and_fields_are_rejected_when_building() {
    let d = dictionary(include_str!("../dialects/illustrative-rupay.json"));
    let mut msg = Iso8583Message::new("0100").unwrap();
    msg.set(4, &b"150000"[..]).unwrap(); // FIXED 12
    assert_eq!(pack(&msg, &d),
               Err(PackError::Field(FieldError::WrongLength { field: 4, expected: 12, actual: 6 })));
    msg.set(4, &b"00000015000A"[..]).unwrap();
    assert!(matches!(pack(&msg, &d), Err(PackError::Field(FieldError::BadFormat { field: 4, .. }))));
    msg.set(4, &b"000000150000"[..]).unwrap();
    msg.set(5, &b"x"[..]).unwrap(); // not in the dialect
    assert_eq!(pack(&msg, &d), Err(PackError::Field(FieldError::Undefined(5))));

    assert_eq!(msg.set(65, &b"x"[..]), Err(BitmapError::ReservedField(65)));
    assert!(Iso8583Message::new("01X0").is_none() && Iso8583Message::new("100").is_none());
    assert!(Dictionary::from_json(r#"{"required": {"0100": [2]}}"#).is_err(), "required field must be defined");
}

/// Task 3.6 acceptance: malformed messages fail fast with descriptive errors, parsing and building.
#[test]
fn field_validators_fail_fast_with_descriptive_errors() {
    let d = dictionary(include_str!("../dialects/illustrative-rupay.json"));
    let wire = rupay_auth_request();
    let de4 = 4 + 16 + 2 + 16 + 6; // MTI, two bitmaps, DE 2 (prefix + 16), DE 3

    // n field containing a letter.
    let mut letter = wire.clone();
    letter[de4 + 5] = b'A';
    let err = unpack(&letter, &d).unwrap_err();
    assert_eq!(err, ParseError::Field(FieldError::BadFormat { field: 4, format: iso8583::Format::Numeric }));
    assert_eq!(err.to_string(), "field 4 doesn't match format Numeric");

    // LLVAR length prefix over the field's maximum: DE 2 says 20, max is 19.
    let mut long = wire.clone();
    long[20..22].copy_from_slice(b"20");
    let err = unpack(&long, &d).unwrap_err();
    assert_eq!(err, ParseError::Field(FieldError::LengthExceeded { field: 2, max: 19, actual: 20 }));
    assert_eq!(err.to_string(), "field 2 is 20 long, over its maximum of 19");

    // MTI not 4 digits.
    assert_eq!(unpack(b"010", &d).unwrap_err(), ParseError::InvalidMti);
    assert!(Iso8583Message::new("01000").is_none() && Iso8583Message::new("010").is_none());

    // Builder: the same rules.
    let mut msg = Iso8583Message::new("0100").unwrap();
    msg.set(2, &b"65210000000000000001"[..]).unwrap(); // 20 digits
    assert_eq!(pack(&msg, &d).unwrap_err().to_string(), "field 2 is 20 long, over its maximum of 19");
    msg.set(2, &b"652100000000000A"[..]).unwrap();
    assert_eq!(pack(&msg, &d), Err(PackError::Field(FieldError::BadFormat { field: 2, format: iso8583::Format::Numeric })));
}
