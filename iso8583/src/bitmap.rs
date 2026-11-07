//! ISO 8583 bitmaps (DE 1): which data elements a message carries.
//!
//! Binary bitmaps, 8 bytes each, most significant bit first: bit 1 is the top bit of the first byte.
//! Bit 1 of each bitmap says another bitmap follows, so fields 1, 65 and 129 are continuation bits that
//! this type derives on encode and strips on parse; callers only ever deal with data fields.
//!
//! shortcut: binary bitmaps only; hex-ASCII bitmaps (16 chars each) come with the per-dialect schema.

use std::fmt;

/// Primary, secondary, tertiary: fields 1-192.
pub const MAX_BITMAPS: usize = 3;
/// The highest field number: 192.
pub const MAX_FIELD: u8 = (MAX_BITMAPS * 64) as u8;
const BITMAP_LEN: usize = 8;

/// Why a bitmap couldn't be read or a field number couldn't be set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BitmapError {
    /// Fewer bytes than the bitmaps announce.
    Truncated { needed: usize, available: usize },
    /// Not a data field number (0, or above 192).
    FieldOutOfRange(u8),
    /// 1, 65 or 129: the continuation bits, which the bitmap manages itself.
    ReservedField(u8),
    /// The tertiary bitmap's bit 1 asks for a fourth bitmap, which ISO 8583 doesn't define.
    TooManyBitmaps,
}

impl fmt::Display for BitmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(f, "bitmap truncated: needed {needed} bytes, got {available}")
            }
            Self::FieldOutOfRange(n) => write!(f, "field {n} is outside 1-{MAX_FIELD}"),
            Self::ReservedField(n) => write!(f, "field {n} is a bitmap continuation bit, not a data field"),
            Self::TooManyBitmaps => write!(f, "tertiary bitmap's bit 1 is set, but there is no fourth bitmap"),
        }
    }
}

impl std::error::Error for BitmapError {}

/// The data fields present in a message. Copy, no heap: cheap to build per message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bitmap {
    words: [u64; MAX_BITMAPS], // data bits only; continuation bits are always clear here
}

fn is_continuation(field: u8) -> bool {
    field % 64 == 1
}

/// (word index, mask) for a field number in 1..=MAX_FIELD.
fn position(field: u8) -> (usize, u64) {
    let i = usize::from(field - 1);
    (i / 64, 1u64 << (63 - i % 64))
}

impl Bitmap {
    /// An empty bitmap: no data fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// A bitmap with exactly these data fields set.
    pub fn from_fields(fields: impl IntoIterator<Item = u8>) -> Result<Self, BitmapError> {
        let mut bitmap = Self::new();
        for field in fields {
            bitmap.set(field)?;
        }
        Ok(bitmap)
    }

    /// Marks a data field present. Rejects 0, numbers above 192, and the continuation bits 1, 65 and 129.
    pub fn set(&mut self, field: u8) -> Result<(), BitmapError> {
        if field == 0 || field > MAX_FIELD {
            return Err(BitmapError::FieldOutOfRange(field));
        }
        if is_continuation(field) {
            return Err(BitmapError::ReservedField(field));
        }
        let (word, mask) = position(field);
        self.words[word] |= mask;
        Ok(())
    }

    /// Whether a data field is present. Continuation bits and out-of-range numbers are never "present".
    pub fn contains(&self, field: u8) -> bool {
        if field == 0 || field > MAX_FIELD || is_continuation(field) {
            return false;
        }
        let (word, mask) = position(field);
        self.words[word] & mask != 0
    }

    /// The data fields present, in ascending order: the order their values appear in the message.
    pub fn fields(&self) -> impl Iterator<Item = u8> + '_ {
        (2..=MAX_FIELD).filter(move |&field| self.contains(field))
    }

    /// How many 8-byte bitmaps the message needs: the last one holding a data field, at least the primary.
    pub fn bitmap_count(&self) -> usize {
        self.words.iter().rposition(|&w| w != 0).map_or(1, |last| last + 1)
    }

    /// Appends the encoded bitmaps (8, 16 or 24 bytes) to `out`, setting each continuation bit.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let count = self.bitmap_count();
        for (i, &word) in self.words[..count].iter().enumerate() {
            let continued = if i + 1 < count { 1u64 << 63 } else { 0 };
            out.extend_from_slice(&(word | continued).to_be_bytes());
        }
    }

    /// Reads the bitmaps at the start of `input`. Returns the bitmap and how many bytes it took
    /// (the data elements start there). Doesn't copy `input`.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), BitmapError> {
        let mut bitmap = Self::new();
        let mut offset = 0;
        for word in &mut bitmap.words {
            let Some(chunk) = input.get(offset..offset + BITMAP_LEN) else {
                return Err(BitmapError::Truncated { needed: offset + BITMAP_LEN, available: input.len() });
            };
            offset += BITMAP_LEN;
            let raw = u64::from_be_bytes(chunk.try_into().expect("slice is BITMAP_LEN bytes"));
            *word = raw & !(1u64 << 63);
            if raw >> 63 == 0 {
                return Ok((bitmap, offset));
            }
        }
        Err(BitmapError::TooManyBitmaps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn encoded(fields: &[u8]) -> String {
        let mut out = Vec::new();
        Bitmap::from_fields(fields.iter().copied()).unwrap().encode_into(&mut out);
        hex(&out)
    }

    #[test]
    fn de_2_3_4_49_build_the_expected_primary_bitmap() {
        // Bits 2-4 → first byte 0111 0000; bit 49 → top bit of byte 7. No secondary, so bit 1 stays clear.
        assert_eq!(encoded(&[2, 3, 4, 49]), "7000000000008000");
    }

    #[test]
    fn a_field_above_64_adds_the_secondary_bitmap() {
        // Bit 1 set (secondary follows) + bit 2; DE 102 is the 6th bit of the secondary's 5th byte.
        assert_eq!(encoded(&[2, 102]), "C0000000000000000000000004000000");
    }

    #[test]
    fn a_field_above_128_adds_secondary_and_tertiary() {
        // The secondary carries only its continuation bit (65) when no field 66-128 is present.
        assert_eq!(encoded(&[3, 130]), "A000000000000000_8000000000000000_4000000000000000".replace('_', ""));
    }

    #[test]
    fn parse_reads_exactly_the_bitmaps_and_stops() {
        let mut msg = unhex("7000000000008000");
        msg.extend_from_slice(b"rest of the message");
        let (bitmap, consumed) = Bitmap::parse(&msg).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(bitmap.fields().collect::<Vec<_>>(), [2, 3, 4, 49]);

        let (bitmap, consumed) = Bitmap::parse(&unhex("C0000000000000000000000004000000")).unwrap();
        assert_eq!(consumed, 16);
        assert_eq!(bitmap.fields().collect::<Vec<_>>(), [2, 102]);
        assert!(!bitmap.contains(1), "continuation bits aren't data fields");
    }

    #[test]
    fn every_single_field_round_trips() {
        for field in (2..=MAX_FIELD).filter(|&f| !is_continuation(f)) {
            let built = Bitmap::from_fields([field]).unwrap();
            let mut out = Vec::new();
            built.encode_into(&mut out);
            assert_eq!(out.len(), 8 * (usize::from(field - 1) / 64 + 1), "field {field}");
            assert_eq!(Bitmap::parse(&out).unwrap(), (built, out.len()), "field {field}");
        }
    }

    #[test]
    fn empty_bitmap_is_one_zero_primary() {
        assert_eq!(encoded(&[]), "0000000000000000");
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert_eq!(Bitmap::parse(&unhex("70000000")),
                   Err(BitmapError::Truncated { needed: 8, available: 4 }));
        // Bit 1 promises a secondary bitmap that isn't there.
        assert_eq!(Bitmap::parse(&unhex("F000000000000000")),
                   Err(BitmapError::Truncated { needed: 16, available: 8 }));
    }

    #[test]
    fn fourth_bitmap_is_rejected() {
        // Bit 1 set in all three bitmaps.
        assert_eq!(Bitmap::parse(&unhex(&"8000000000000000".repeat(3))), Err(BitmapError::TooManyBitmaps));
    }

    #[test]
    fn invalid_field_numbers_are_rejected() {
        let mut bitmap = Bitmap::new();
        for reserved in [1, 65, 129] {
            assert_eq!(bitmap.set(reserved), Err(BitmapError::ReservedField(reserved)));
        }
        assert_eq!(bitmap.set(0), Err(BitmapError::FieldOutOfRange(0)));
        assert_eq!(bitmap.set(193), Err(BitmapError::FieldOutOfRange(193)));
        assert_eq!(bitmap, Bitmap::new());
    }
}
