//! Field dictionary: per-host JSON describing how each data element is laid out on the wire.
//!
//! ```json
//! { "2": { "type": "LLVAR", "max_length": 19, "format": "n" },
//!   "4": { "type": "FIXED", "length": 12, "format": "n" } }
//! ```
//! Lengths count characters (digits for `n`, bytes for `b`). Optional per-field keys, both default `ascii`:
//! - `"encoding": "bcd"`: the value is packed BCD, two digits per byte (only for `n` fields);
//! - `"prefix": "bcd"`: the LL/LLL length is packed BCD (1 byte for LL, 2 for LLL).
//!
//! Odd digit counts are left-padded with a 0 nibble.
//!
//! An optional top-level `"required"` key lists, per MTI, the fields a message must carry to be packed:
//! `"required": { "0100": [2, 3, 4, 11] }`. Two more optional top-level keys describe the message frame:
//! `"mti": "ascii" | "bcd"` and `"bitmap": "binary" | "hex"` (defaults `ascii`, `binary`).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::bitmap::{Bitmap, BitmapEncoding, BitmapError, MAX_FIELD};

/// Which characters a field may hold (the JSON `format` key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub enum Format {
    /// Digits 0-9.
    #[serde(rename = "n")]
    Numeric,
    /// Letters and digits.
    #[serde(rename = "an")]
    Alphanumeric,
    /// Letters, digits, space and printable special characters.
    #[serde(rename = "ans")]
    AlphanumericSpecial,
    /// Any bytes.
    #[serde(rename = "b")]
    Binary,
}

impl Format {
    fn accepts(self, value: &[u8]) -> bool {
        match self {
            Self::Numeric => value.iter().all(u8::is_ascii_digit),
            Self::Alphanumeric => value.iter().all(u8::is_ascii_alphanumeric),
            Self::AlphanumericSpecial => value.iter().all(|b| (0x20..=0x7E).contains(b)),
            Self::Binary => true,
        }
    }
}

/// How characters are carried on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Encoding {
    /// One character per byte.
    #[default]
    Ascii,
    /// Packed binary-coded decimal: two digits per byte.
    Bcd,
}

impl Encoding {
    /// Bytes on the wire for `chars` characters.
    pub(crate) fn wire_len(self, chars: usize) -> usize {
        match self {
            Self::Ascii => chars,
            Self::Bcd => chars.div_ceil(2),
        }
    }

    /// The `chars` characters in `raw`, as ASCII. None for invalid BCD (a nibble above 9, or a non-zero pad).
    pub(crate) fn decode(self, raw: &[u8], chars: usize) -> Option<Cow<'_, [u8]>> {
        match self {
            Self::Ascii => Some(Cow::Borrowed(raw)),
            Self::Bcd => {
                let pad = raw.len() * 2 - chars; // 0 or 1 leading pad nibble
                if pad == 1 && raw[0] >> 4 != 0 {
                    return None;
                }
                let nibbles = raw.iter().flat_map(|b| [b >> 4, b & 0x0F]).skip(pad);
                nibbles.map(|n| (n <= 9).then_some(b'0' + n)).collect::<Option<Vec<_>>>().map(Cow::Owned)
            }
        }
    }

    /// Appends ASCII `text` in this encoding. For BCD, `text` must be all digits.
    pub(crate) fn encode(self, text: &[u8], out: &mut Vec<u8>) {
        match self {
            Self::Ascii => out.extend_from_slice(text),
            Self::Bcd => {
                let digits = text.iter().map(|d| d - b'0');
                let padded: Vec<u8> = std::iter::repeat_n(0, text.len() % 2).chain(digits).collect();
                out.extend(padded.chunks(2).map(|pair| pair[0] << 4 | pair[1]));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE", deny_unknown_fields)]
/// How one field is laid out: its length rule (the JSON `type` key) plus format and encodings.
#[non_exhaustive]
pub enum FieldSpec {
    /// Always exactly `length` characters; no length prefix.
    #[non_exhaustive]
    Fixed {
        /// Characters (digits for BCD, bytes for `b`).
        length: usize,
        /// Allowed characters.
        format: Format,
        /// How the value is carried.
        #[serde(default)]
        encoding: Encoding,
    },
    /// Variable length up to `max_length` (at most 99), after a 2-digit length prefix.
    #[non_exhaustive]
    Llvar {
        /// Longest value allowed, in characters.
        max_length: usize,
        /// Allowed characters.
        format: Format,
        /// How the value is carried.
        #[serde(default)]
        encoding: Encoding,
        /// How the length prefix is carried.
        #[serde(default)]
        prefix: Encoding,
    },
    /// Variable length up to `max_length` (at most 999), after a 3-digit length prefix.
    #[non_exhaustive]
    Lllvar {
        /// Longest value allowed, in characters.
        max_length: usize,
        /// Allowed characters.
        format: Format,
        /// How the value is carried.
        #[serde(default)]
        encoding: Encoding,
        /// How the length prefix is carried.
        #[serde(default)]
        prefix: Encoding,
    },
}

impl FieldSpec {
    fn format(self) -> Format {
        match self {
            Self::Fixed { format, .. } | Self::Llvar { format, .. } | Self::Lllvar { format, .. } => format,
        }
    }

    fn encoding(self) -> Encoding {
        match self {
            Self::Fixed { encoding, .. } | Self::Llvar { encoding, .. } | Self::Lllvar { encoding, .. } => encoding,
        }
    }

    fn prefix_encoding(self) -> Encoding {
        match self {
            Self::Fixed { .. } => Encoding::Ascii,
            Self::Llvar { prefix, .. } | Self::Lllvar { prefix, .. } => prefix,
        }
    }

    /// Digits in the length prefix: 0 for fixed fields.
    fn prefix_digits(self) -> usize {
        match self {
            Self::Fixed { .. } => 0,
            Self::Llvar { .. } => 2,
            Self::Lllvar { .. } => 3,
        }
    }

    fn validate(self) -> Result<(), String> {
        match self {
            Self::Fixed { length: 0, .. } => Err("FIXED length must be at least 1".into()),
            Self::Llvar { max_length, .. } if max_length > 99 => Err("LLVAR max_length can't exceed 99".into()),
            Self::Lllvar { max_length, .. } if max_length > 999 => Err("LLLVAR max_length can't exceed 999".into()),
            _ if self.encoding() == Encoding::Bcd && self.format() != Format::Numeric => {
                Err("bcd encoding needs format n".into())
            }
            _ => Ok(()),
        }
    }
}

/// Why a field couldn't be read or written. Never carries the field's value (it may be a PAN).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldError {
    /// The dictionary has no entry for this field.
    Undefined(u8),
    /// The input ends before the field (or its length prefix) does.
    Truncated { field: u8, needed: usize, available: usize },
    /// The length prefix isn't all digits.
    BadLengthPrefix(u8),
    /// An LLVAR/LLLVAR value (or its length prefix) is longer than the field's max_length.
    LengthExceeded { field: u8, max: usize, actual: usize },
    /// A FIXED value isn't exactly the field's length.
    WrongLength { field: u8, expected: usize, actual: usize },
    /// The value contains characters its format doesn't allow.
    BadFormat { field: u8, format: Format },
}

impl fmt::Display for FieldError {
    // Never includes the field's value: it may be a PAN or track data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undefined(n) => write!(f, "field {n} isn't defined in the dictionary"),
            Self::Truncated { field, needed, available } => {
                write!(f, "field {field} truncated: needed {needed} bytes, {available} available")
            }
            Self::BadLengthPrefix(n) => write!(f, "field {n} has a non-numeric length prefix"),
            Self::LengthExceeded { field, max, actual } => {
                write!(f, "field {field} is {actual} long, over its maximum of {max}")
            }
            Self::WrongLength { field, expected, actual } => {
                write!(f, "field {field} is {actual} long; it must be exactly {expected}")
            }
            Self::BadFormat { field, format } => write!(f, "field {field} doesn't match format {format:?}"),
        }
    }
}

impl std::error::Error for FieldError {}

/// Why a dictionary JSON file was rejected; the message names the offending key or field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryError(pub String);

impl fmt::Display for DictionaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid field dictionary: {}", self.0)
    }
}

impl std::error::Error for DictionaryError {}

/// One host dialect's field definitions, indexed by field number.
#[derive(Debug, Clone)]
pub struct Dictionary {
    fields: [Option<FieldSpec>; MAX_FIELD as usize + 1],
    required: BTreeMap<String, Vec<u8>>, // MTI → fields
    mti: Encoding,
    bitmap: BitmapEncoding,
}

/// Removes and parses an optional top-level key; its default when absent.
fn take<T: DeserializeOwned + Default>(raw: &mut BTreeMap<String, serde_json::Value>, key: &str)
    -> Result<T, DictionaryError> {
    raw.remove(key).map(serde_json::from_value).transpose()
        .map_err(|e| DictionaryError(format!("{key}: {e}")))
        .map(Option::unwrap_or_default)
}

impl Dictionary {
    /// Loads and checks a dictionary (see the crate docs for the format). Fails on unknown keys, impossible
    /// lengths, BCD on non-numeric fields, and `required` fields the dictionary doesn't define.
    pub fn from_json(json: &str) -> Result<Self, DictionaryError> {
        let invalid = |e: serde_json::Error| DictionaryError(e.to_string());
        let mut raw: BTreeMap<String, serde_json::Value> = serde_json::from_str(json).map_err(invalid)?;
        let required: BTreeMap<String, Vec<u8>> = take(&mut raw, "required")?;
        let mti = take(&mut raw, "mti")?;
        let bitmap = take(&mut raw, "bitmap")?;

        let mut fields = [None; MAX_FIELD as usize + 1];
        for (key, value) in raw {
            let field: u8 = key.parse().map_err(|_| DictionaryError(format!("\"{key}\" isn't a field number")))?;
            Bitmap::from_fields([field]).map_err(|e: BitmapError| DictionaryError(e.to_string()))?;
            let spec: FieldSpec = serde_json::from_value(value)
                .map_err(|e| DictionaryError(format!("field {field}: {e}")))?;
            spec.validate().map_err(|e| DictionaryError(format!("field {field}: {e}")))?;
            fields[usize::from(field)] = Some(spec);
        }
        for (mti, required_fields) in &required {
            if mti.len() != 4 || !mti.bytes().all(|b| b.is_ascii_digit()) {
                return Err(DictionaryError(format!("required: \"{mti}\" isn't an MTI")));
            }
            if let Some(f) = required_fields.iter().find(|&&f| fields.get(usize::from(f)).copied().flatten().is_none()) {
                return Err(DictionaryError(format!("required: field {f} for {mti} isn't defined")));
            }
        }
        Ok(Self { fields, required, mti, bitmap })
    }

    /// How the 4-digit MTI is carried: 4 ASCII bytes, or 2 BCD bytes.
    pub fn mti_encoding(&self) -> Encoding {
        self.mti
    }

    /// How the bitmaps are carried: 8 binary bytes, or 16 hex characters, each.
    pub fn bitmap_encoding(&self) -> BitmapEncoding {
        self.bitmap
    }

    /// The field's layout, or None if this dialect doesn't define it.
    pub fn spec(&self, field: u8) -> Option<FieldSpec> {
        self.fields.get(usize::from(field)).copied().flatten()
    }

    /// Fields a message with this MTI must carry; empty if the dialect sets no rule for it.
    pub fn required(&self, mti: &str) -> &[u8] {
        self.required.get(mti).map_or(&[], Vec::as_slice)
    }

    /// Reads `field` from the start of `input`. Returns the value (length prefix excluded; BCD decoded to
    /// ASCII digits, otherwise borrowed from `input`) and how many bytes the field took, so the caller can
    /// move on to the next field.
    pub fn read<'a>(&self, field: u8, input: &'a [u8]) -> Result<(Cow<'a, [u8]>, usize), FieldError> {
        let spec = self.spec(field).ok_or(FieldError::Undefined(field))?;
        let prefix = spec.prefix_encoding().wire_len(spec.prefix_digits());
        let length = match spec {
            FieldSpec::Fixed { length, .. } => length,
            FieldSpec::Llvar { max_length, .. } | FieldSpec::Lllvar { max_length, .. } => {
                let raw = input.get(..prefix).ok_or(FieldError::Truncated {
                    field, needed: prefix, available: input.len(),
                })?;
                let digits = spec.prefix_encoding().decode(raw, spec.prefix_digits())
                    .filter(|d| d.iter().all(u8::is_ascii_digit))
                    .ok_or(FieldError::BadLengthPrefix(field))?;
                let length = digits.iter().fold(0, |n, d| n * 10 + usize::from(d - b'0'));
                if length > max_length {
                    return Err(FieldError::LengthExceeded { field, max: max_length, actual: length });
                }
                length
            }
        };
        let wire = spec.encoding().wire_len(length);
        let raw = input.get(prefix..prefix + wire).ok_or(FieldError::Truncated {
            field, needed: prefix + wire, available: input.len(),
        })?;
        let value = spec.encoding().decode(raw, length)
            .filter(|v| spec.format().accepts(v))
            .ok_or(FieldError::BadFormat { field, format: spec.format() })?;
        Ok((value, prefix + wire))
    }

    /// Appends `field` (with its length prefix, if any) to `out`. Nothing is written on error.
    pub fn write(&self, field: u8, value: &[u8], out: &mut Vec<u8>) -> Result<(), FieldError> {
        let spec = self.spec(field).ok_or(FieldError::Undefined(field))?;
        let actual = value.len();
        match spec {
            FieldSpec::Fixed { length, .. } if actual != length => {
                return Err(FieldError::WrongLength { field, expected: length, actual });
            }
            FieldSpec::Llvar { max_length, .. } | FieldSpec::Lllvar { max_length, .. } if actual > max_length => {
                return Err(FieldError::LengthExceeded { field, max: max_length, actual });
            }
            _ => {}
        }
        if !spec.format().accepts(value) {
            return Err(FieldError::BadFormat { field, format: spec.format() });
        }
        if spec.prefix_digits() > 0 {
            let length = format!("{:0width$}", value.len(), width = spec.prefix_digits());
            spec.prefix_encoding().encode(length.as_bytes(), out);
        }
        spec.encoding().encode(value, out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../dialects/example.json");

    fn dict() -> Dictionary {
        Dictionary::from_json(EXAMPLE).unwrap()
    }

    #[test]
    fn reads_variable_de_2_and_fixed_de_4_by_the_dictionary() {
        // DE 2 (LLVAR): "16" + 16-digit PAN = 18 bytes. DE 4 (FIXED 12): 12 bytes, no prefix.
        let wire = b"164111111111111111000000050000";
        let (pan, used) = dict().read(2, wire).unwrap();
        assert_eq!((&*pan, used), (&b"4111111111111111"[..], 18));
        let (amount, used) = dict().read(4, &wire[18..]).unwrap();
        assert_eq!((&*amount, used), (&b"000000050000"[..], 12));
        assert!(std::ptr::eq(pan.as_ptr(), wire[2..].as_ptr()), "value borrows the input");
    }

    #[test]
    fn the_same_bytes_are_cut_differently_per_field() {
        let wire = b"123456789012345678901234";
        assert_eq!(dict().read(3, wire).unwrap().1, 6);
        assert_eq!(dict().read(4, wire).unwrap().1, 12);
        assert_eq!(dict().read(2, wire).unwrap().1, 14); // prefix "12" → 12 digits
        assert_eq!(dict().read(48, b"005hello").unwrap(), (Cow::Borrowed(&b"hello"[..]), 8));
    }

    #[test]
    fn write_then_read_round_trips() {
        let d = dict();
        let mut out = Vec::new();
        d.write(2, b"4111111111111111", &mut out).unwrap();
        d.write(39, b"00", &mut out).unwrap();
        d.write(48, b"", &mut out).unwrap();
        assert_eq!(out, b"16411111111111111100000");
        let (_, a) = d.read(2, &out).unwrap();
        let (_, b) = d.read(39, &out[a..]).unwrap();
        assert_eq!(d.read(48, &out[a + b..]).unwrap(), (Cow::Borrowed(&b""[..]), 3));
    }

    #[test]
    fn malformed_fields_are_rejected() {
        let d = dict();
        assert_eq!(d.read(4, b"00000005"), Err(FieldError::Truncated { field: 4, needed: 12, available: 8 }));
        assert_eq!(d.read(2, b"2"), Err(FieldError::Truncated { field: 2, needed: 2, available: 1 }));
        assert_eq!(d.read(2, b"20" as &[u8]), Err(FieldError::LengthExceeded { field: 2, max: 19, actual: 20 }));
        assert_eq!(d.read(2, b"1x41111111111"), Err(FieldError::BadLengthPrefix(2)));
        assert_eq!(d.read(4, b"00000005000A"), Err(FieldError::BadFormat { field: 4, format: Format::Numeric }));
        assert_eq!(d.read(39, b"0 "), Err(FieldError::BadFormat { field: 39, format: Format::Alphanumeric }));
        assert_eq!(d.read(5, b"x"), Err(FieldError::Undefined(5)));

        let mut out = b"kept".to_vec();
        assert_eq!(d.write(4, b"123", &mut out), Err(FieldError::WrongLength { field: 4, expected: 12, actual: 3 }));
        assert_eq!(d.write(2, &[b'4'; 20], &mut out),
                   Err(FieldError::LengthExceeded { field: 2, max: 19, actual: 20 }));
        assert_eq!(out, b"kept", "nothing written on error");
    }

    #[test]
    fn invalid_dictionaries_are_rejected() {
        for bad in [
            r#"{"65": {"type": "FIXED", "length": 8, "format": "b"}}"#,       // continuation bit
            r#"{"200": {"type": "FIXED", "length": 1, "format": "n"}}"#,      // no such field
            r#"{"2": {"type": "LLVAR", "max_length": 100, "format": "n"}}"#,  // LL can't say 100
            r#"{"3": {"type": "FIXED", "length": 0, "format": "n"}}"#,
            r#"{"3": {"type": "FIXED", "length": 6, "format": "x"}}"#,        // unknown format
            r#"{"3": {"type": "FIXED", "length": 6, "format": "n", "pad": "0"}}"#, // unknown key
            r#"{"two": {"type": "FIXED", "length": 6, "format": "n"}}"#,
        ] {
            assert!(Dictionary::from_json(bad).is_err(), "{bad}");
        }
    }

    const BCD: &str = r#"{
        "2": { "type": "LLVAR", "max_length": 19, "format": "n", "encoding": "bcd", "prefix": "bcd" },
        "4": { "type": "FIXED", "length": 12, "format": "n", "encoding": "bcd" },
        "49": { "type": "FIXED", "length": 3, "format": "n", "encoding": "bcd" },
        "55": { "type": "LLLVAR", "max_length": 255, "format": "b", "prefix": "bcd" }
    }"#;

    #[test]
    fn bcd_fields_and_prefixes() {
        let d = Dictionary::from_json(BCD).unwrap();
        // LL prefix is 1 BCD byte (0x16); 16 digits pack into 8 bytes.
        let wire = [0x16, 0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
        assert_eq!(d.read(2, &wire).unwrap(), (Cow::Owned(b"4111111111111111".to_vec()), 9));
        assert_eq!(d.read(4, &[0x00, 0x00, 0x00, 0x15, 0x00, 0x00]).unwrap().0.as_ref(), b"000000150000");
        assert_eq!(d.read(49, &[0x08, 0x40]).unwrap().0.as_ref(), b"840"); // odd: leading 0 pad nibble
        // LLL prefix is 2 BCD bytes (0x0003); a binary value stays borrowed.
        assert_eq!(d.read(55, &[0x00, 0x03, 0x91, 0x01, 0xFF]).unwrap(),
                   (Cow::Borrowed(&[0x91, 0x01, 0xFF][..]), 5));

        let mut out = Vec::new();
        d.write(49, b"840", &mut out).unwrap();
        d.write(2, b"4111111111111111", &mut out).unwrap();
        assert_eq!(out, [0x08, 0x40, 0x16, 0x41, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]);
    }

    #[test]
    fn invalid_bcd_is_rejected() {
        let d = Dictionary::from_json(BCD).unwrap();
        let numeric = FieldError::BadFormat { field: 49, format: Format::Numeric };
        assert_eq!(d.read(49, &[0x18, 0x40]), Err(numeric.clone()), "pad nibble must be 0");
        assert_eq!(d.read(49, &[0x08, 0x4A]), Err(numeric));
        assert_eq!(d.read(2, &[0x1A]), Err(FieldError::BadLengthPrefix(2)));
        let ans_bcd = r#"{"41": {"type": "FIXED", "length": 8, "format": "ans", "encoding": "bcd"}}"#;
        assert!(Dictionary::from_json(ans_bcd).is_err(), "bcd needs format n");
    }

    #[test]
    fn errors_never_contain_the_value() {
        let err = dict().read(2, b"16411111111111111X").unwrap_err();
        assert!(!err.to_string().contains("4111"), "{err}");
    }
}
