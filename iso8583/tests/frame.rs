//! 1.1.0: dialect-level framing options, `"mti": "bcd"` and `"bitmap": "hex"`.

use iso8583::{pack, unpack, BitmapEncoding, BitmapError, Dictionary, Encoding, Iso8583Message, ParseError};

const BCD_MTI_HEX_BITMAP: &str = r#"{
    "mti": "bcd",
    "bitmap": "hex",
    "3": { "type": "FIXED", "length": 6, "format": "n" },
    "4": { "type": "FIXED", "length": 12, "format": "n", "encoding": "bcd" },
    "70": { "type": "FIXED", "length": 3, "format": "n" }
}"#;

/// Written out by hand, not by the builder.
fn network_echo() -> Vec<u8> {
    [
        &[0x08, 0x00][..],                            // MTI 0800, 2 BCD bytes
        b"A000000000000000",                          // primary, hex: bits 1 (secondary follows) and 3
        b"0400000000000000",                          // secondary, hex: bit 70
        b"990000",                                    // DE 3
        b"301",                                       // DE 70
    ]
    .concat()
}

#[test]
fn bcd_mti_and_hex_bitmap_parse_and_build() {
    let d = Dictionary::from_json(BCD_MTI_HEX_BITMAP).unwrap();
    assert_eq!((d.mti_encoding(), d.bitmap_encoding()), (Encoding::Bcd, BitmapEncoding::Hex));

    let wire = network_echo();
    let msg = unpack(&wire, &d).unwrap();
    assert_eq!(msg.mti(), "0800");
    assert_eq!(msg.fields().collect::<Vec<_>>(), [3, 70]);
    assert_eq!((msg.get_str(3), msg.get_str(70)), (Some("990000"), Some("301")));
    assert_eq!(pack(&msg, &d).unwrap(), wire, "round trip");

    let mut built = Iso8583Message::new("0800").unwrap();
    built.set(70, &b"301"[..]).unwrap();
    built.set(3, &b"990000"[..]).unwrap();
    assert_eq!(pack(&built, &d).unwrap(), wire, "built from scratch");
}

#[test]
fn defaults_are_ascii_mti_and_binary_bitmap() {
    let d = Dictionary::from_json(r#"{ "3": { "type": "FIXED", "length": 6, "format": "n" } }"#).unwrap();
    assert_eq!((d.mti_encoding(), d.bitmap_encoding()), (Encoding::Ascii, BitmapEncoding::Binary));
    let mut msg = Iso8583Message::new("0800").unwrap();
    msg.set(3, &b"990000"[..]).unwrap();
    assert_eq!(pack(&msg, &d).unwrap(), [&b"0800"[..], &[0x20, 0, 0, 0, 0, 0, 0, 0], b"990000"].concat());
}

#[test]
fn malformed_frames_are_rejected() {
    let d = Dictionary::from_json(BCD_MTI_HEX_BITMAP).unwrap();
    let mut wire = network_echo();
    wire[0] = 0x0A; // not a decimal nibble
    assert_eq!(unpack(&wire, &d).unwrap_err(), ParseError::InvalidMti);
    assert_eq!(unpack(&[0x08], &d).unwrap_err(), ParseError::InvalidMti);

    let mut lowercase = network_echo();
    lowercase[2] = b'a'; // "a000..." instead of "A000..."
    assert_eq!(unpack(&lowercase, &d).unwrap_err(), ParseError::Bitmap(BitmapError::InvalidHex));

    for bad in [r#"{"mti": "ebcdic"}"#, r#"{"bitmap": "base64"}"#, r#"{"bitmap": 8}"#] {
        assert!(Dictionary::from_json(bad).is_err(), "{bad}");
    }
}
