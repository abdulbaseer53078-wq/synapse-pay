//! Packing: [`Iso8583Message`] + a host [`Dictionary`] → raw bytes. The inverse of [`unpack`](crate::unpack):
//! for any message `unpack` accepts, `pack(unpack(raw)) == raw`.

use std::fmt;

use crate::bitmap::{Bitmap, BitmapError};
use crate::dictionary::{Dictionary, FieldError};
use crate::message::Iso8583Message;

/// Why [`pack`] couldn't build a message. Never carries field values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackError {
    /// The dictionary requires this field for the message's MTI, and the message doesn't have it.
    MissingField(u8),
    /// A field number can't appear in a bitmap.
    Bitmap(BitmapError),
    /// A value doesn't fit its field's definition.
    Field(FieldError),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(n) => write!(f, "required field {n} is missing"),
            Self::Bitmap(e) => write!(f, "{e}"),
            Self::Field(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PackError {}

/// MTI, then the bitmaps generated from the fields present, then each field in ascending order with its
/// length prefix, encoded (ASCII or BCD) as the dictionary says.
pub fn pack(msg: &Iso8583Message, dictionary: &Dictionary) -> Result<Vec<u8>, PackError> {
    if let Some(&missing) = dictionary.required(msg.mti()).iter().find(|&&f| msg.get(f).is_none()) {
        return Err(PackError::MissingField(missing));
    }
    let bitmap = Bitmap::from_fields(msg.fields()).map_err(PackError::Bitmap)?;

    let mut out = Vec::with_capacity(256);
    dictionary.mti_encoding().encode(msg.mti().as_bytes(), &mut out);
    bitmap.encode_as(dictionary.bitmap_encoding(), &mut out);
    for field in msg.fields() {
        let value = msg.get(field).expect("fields() lists only present fields");
        dictionary.write(field, value, &mut out).map_err(PackError::Field)?;
    }
    Ok(out)
}
