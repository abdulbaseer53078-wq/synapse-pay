//! Unpacking: raw bytes + a host [`Dictionary`] → [`Iso8583Message`].
//!
//! Strict by design: a bit set for a field the dictionary doesn't define, a malformed field or bytes left
//! over all mean the parser has lost its alignment, so they fail instead of guessing.
//!
//! shortcut: ASCII MTI and no message header (e.g. Visa's); add both to the dictionary when a host that
//! needs them is onboarded.

use std::borrow::Cow;
use std::fmt;

use crate::bitmap::{Bitmap, BitmapError};
use crate::dictionary::{Dictionary, FieldError};

const MTI_LEN: usize = 4;

/// A parsed message. Values borrow from the input buffer; only BCD fields are decoded into new memory.
pub struct Iso8583Message<'a> {
    mti: [u8; MTI_LEN],
    fields: Vec<(u8, Cow<'a, [u8]>)>, // ascending field number, as in the bitmap
}

impl Iso8583Message<'_> {
    /// The message type indicator, e.g. `"0100"`.
    pub fn mti(&self) -> &str {
        std::str::from_utf8(&self.mti).expect("MTI is validated as 4 decimal digits")
    }

    /// The field's value: text (BCD decoded to digits) or raw bytes for `b` fields.
    pub fn get(&self, field: u8) -> Option<&[u8]> {
        self.fields.binary_search_by_key(&field, |(n, _)| *n).ok().map(|i| self.fields[i].1.as_ref())
    }

    /// The field's value as text; None if absent or not UTF-8 (binary fields).
    pub fn get_str(&self, field: u8) -> Option<&str> {
        self.get(field).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Field numbers present, ascending.
    pub fn fields(&self) -> impl Iterator<Item = u8> + '_ {
        self.fields.iter().map(|(n, _)| *n)
    }
}

impl<'a> Iso8583Message<'a> {
    /// An empty message to fill with [`set`](Self::set) and send with [`pack`](crate::pack()).
    /// None unless `mti` is 4 decimal digits.
    pub fn new(mti: &str) -> Option<Self> {
        let mti: [u8; MTI_LEN] = mti.as_bytes().try_into().ok()?;
        mti.iter().all(u8::is_ascii_digit).then(|| Self { mti, fields: Vec::new() })
    }

    /// Sets a data field, replacing any earlier value. Values are checked against the dictionary at pack time.
    pub fn set(&mut self, field: u8, value: impl Into<Cow<'a, [u8]>>) -> Result<(), BitmapError> {
        Bitmap::new().set(field)?; // same field-number rules as the bitmap: 2-192, no continuation bits
        let value = value.into();
        match self.fields.binary_search_by_key(&field, |(n, _)| *n) {
            Ok(i) => self.fields[i].1 = value,
            Err(i) => self.fields.insert(i, (field, value)),
        }
        Ok(())
    }
}

/// Field numbers and lengths only: values include card numbers, which must never reach a log.
impl fmt::Debug for Iso8583Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iso8583Message")
            .field("mti", &self.mti())
            .field("field_lengths", &self.fields.iter().map(|(n, v)| (*n, v.len())).collect::<Vec<_>>())
            .finish()
    }
}

/// Why [`unpack`] rejected a message. Never carries field values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Missing, or not 4 decimal digits.
    InvalidMti,
    /// The bitmaps are truncated or announce a fourth bitmap.
    Bitmap(BitmapError),
    /// A data field is undefined, truncated or malformed.
    Field(FieldError),
    /// Bytes after the last field the bitmap announced.
    TrailingBytes(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMti => write!(f, "MTI is missing or not 4 decimal digits"),
            Self::Bitmap(e) => write!(f, "{e}"),
            Self::Field(e) => write!(f, "{e}"),
            Self::TrailingBytes(n) => write!(f, "{n} unexpected bytes after the last field"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<BitmapError> for ParseError {
    fn from(e: BitmapError) -> Self {
        Self::Bitmap(e)
    }
}

impl From<FieldError> for ParseError {
    fn from(e: FieldError) -> Self {
        Self::Field(e)
    }
}

/// Parses one message. `input` must hold exactly one message, from the MTI to the last field.
pub fn unpack<'a>(input: &'a [u8], dictionary: &Dictionary) -> Result<Iso8583Message<'a>, ParseError> {
    let mti: [u8; MTI_LEN] = input.get(..MTI_LEN)
        .filter(|m| m.iter().all(u8::is_ascii_digit))
        .ok_or(ParseError::InvalidMti)?
        .try_into().expect("MTI_LEN bytes");

    let (bitmap, consumed) = Bitmap::parse(&input[MTI_LEN..])?;
    let mut pos = MTI_LEN + consumed;

    let mut fields = Vec::with_capacity(bitmap.fields().count());
    for field in bitmap.fields() {
        let (value, used) = dictionary.read(field, &input[pos..])?;
        pos += used;
        fields.push((field, value));
    }

    match input.len() - pos {
        0 => Ok(Iso8583Message { mti, fields }),
        extra => Err(ParseError::TrailingBytes(extra)),
    }
}
