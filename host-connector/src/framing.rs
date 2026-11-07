//! Length-prefix framing: TCP is one byte stream, so each message is sent as `[length header][message]`
//! and the receiver reads exactly the header, then exactly that many bytes.
//!
//! [`Framing::encode`] / [`Framing::decode`] work on buffers, so any transport (blocking or async) can use
//! them; [`Framing::write_frame`] / [`Framing::read_frame`] are the blocking `std::io` versions.
//!
//! shortcut: the length counts the message only, not the header; add an option when a host counts both.

use std::fmt;
use std::io::{self, Read, Write};

/// How the message length is written in front of each message. Set per host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthHeader {
    /// 2 bytes, big-endian unsigned (up to 65,535). The most common.
    Binary2,
    /// 4 bytes, big-endian unsigned.
    Binary4,
    /// 4 ASCII digits, e.g. "0187" (up to 9,999).
    Ascii4,
}

impl LengthHeader {
    pub fn width(self) -> usize {
        match self {
            Self::Binary2 => 2,
            Self::Binary4 | Self::Ascii4 => 4,
        }
    }

    /// The largest length this header can express.
    fn capacity(self) -> usize {
        match self {
            Self::Binary2 => u16::MAX.into(),
            Self::Binary4 => u32::MAX.try_into().unwrap_or(usize::MAX),
            Self::Ascii4 => 9_999,
        }
    }

    fn write(self, len: usize, out: &mut Vec<u8>) {
        match self {
            Self::Binary2 => out.extend_from_slice(&(len as u16).to_be_bytes()),
            Self::Binary4 => out.extend_from_slice(&(len as u32).to_be_bytes()),
            Self::Ascii4 => out.extend_from_slice(format!("{len:04}").as_bytes()),
        }
    }

    /// `header` is exactly `width()` bytes.
    fn read(self, header: &[u8]) -> Result<usize, FrameError> {
        match self {
            Self::Binary2 => Ok(u16::from_be_bytes([header[0], header[1]]).into()),
            Self::Binary4 => u32::from_be_bytes([header[0], header[1], header[2], header[3]])
                .try_into().map_err(|_| FrameError::BadHeader),
            Self::Ascii4 => header.iter().try_fold(0, |n: usize, d| {
                d.is_ascii_digit().then(|| n * 10 + usize::from(d - b'0'))
            }).ok_or(FrameError::BadHeader),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The message (to send, or announced by a received header) is longer than allowed.
    TooLong { len: usize, max: usize },
    /// An ASCII length header that isn't all digits.
    BadHeader,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { len, max } => write!(f, "frame of {len} bytes exceeds the maximum of {max}"),
            Self::BadHeader => write!(f, "length header is not a valid length"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<FrameError> for io::Error {
    fn from(e: FrameError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// One host's framing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framing {
    pub header: LengthHeader,
    /// Largest message accepted or sent. Checked before reading a body, so a corrupt or hostile header
    /// can't make the connector allocate gigabytes.
    pub max_len: usize,
}

impl Framing {
    pub fn new(header: LengthHeader) -> Self {
        Self { header, max_len: 8_192 } // ISO 8583 messages are rarely over 2 KB
    }

    fn check(&self, len: usize) -> Result<(), FrameError> {
        let max = self.max_len.min(self.header.capacity());
        if len > max { Err(FrameError::TooLong { len, max }) } else { Ok(()) }
    }

    /// Appends `[header][msg]` to `out`.
    pub fn encode(&self, msg: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
        self.check(msg.len())?;
        self.header.write(msg.len(), out);
        out.extend_from_slice(msg);
        Ok(())
    }

    /// Splits the first complete frame off the front of `buf`: `Ok(Some((message, bytes consumed)))`, or
    /// `Ok(None)` if `buf` doesn't hold a whole frame yet (read more and call again).
    pub fn decode<'a>(&self, buf: &'a [u8]) -> Result<Option<(&'a [u8], usize)>, FrameError> {
        let width = self.header.width();
        let Some(header) = buf.get(..width) else { return Ok(None) };
        let len = self.header.read(header)?;
        self.check(len)?;
        Ok(buf.get(width..width + len).map(|msg| (msg, width + len)))
    }

    pub fn write_frame(&self, w: &mut impl Write, msg: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(self.header.width() + msg.len());
        self.encode(msg, &mut frame)?;
        w.write_all(&frame) // one write, so the header and body leave together
    }

    /// Reads exactly one frame. `UnexpectedEof` if the stream ends mid-frame (or before one starts).
    pub fn read_frame(&self, r: &mut impl Read) -> io::Result<Vec<u8>> {
        let mut header = [0u8; 4];
        let header = &mut header[..self.header.width()];
        r.read_exact(header)?;
        let len = self.header.read(header)?;
        self.check(len)?;
        let mut msg = vec![0; len];
        r.read_exact(&mut msg)?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(f: Framing, msg: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        f.encode(msg, &mut out).unwrap();
        out
    }

    #[test]
    fn headers_are_written_as_configured() {
        assert_eq!(framed(Framing::new(LengthHeader::Binary2), b"0800"), b"\x00\x040800");
        assert_eq!(framed(Framing::new(LengthHeader::Binary4), b"0800"), b"\x00\x00\x00\x040800");
        assert_eq!(framed(Framing::new(LengthHeader::Ascii4), b"0800"), b"00040800");
        assert_eq!(framed(Framing::new(LengthHeader::Binary2), &[7; 300])[..2], [0x01, 0x2C]); // 300
    }

    #[test]
    fn back_to_back_frames_split_apart_and_partial_frames_wait() {
        for header in [LengthHeader::Binary2, LengthHeader::Binary4, LengthHeader::Ascii4] {
            let f = Framing::new(header);
            let stream = [framed(f, b"first message"), framed(f, b"second")].concat();

            let (one, used) = f.decode(&stream).unwrap().unwrap();
            assert_eq!(one, b"first message");
            let (two, used2) = f.decode(&stream[used..]).unwrap().unwrap();
            assert_eq!((two, used + used2), (&b"second"[..], stream.len()));

            for cut in 0..framed(f, b"first message").len() {
                assert_eq!(f.decode(&stream[..cut]), Ok(None), "{header:?} cut at {cut}");
            }
        }
    }

    #[test]
    fn oversized_and_malformed_headers_are_rejected() {
        let f = Framing { header: LengthHeader::Binary4, max_len: 100 };
        assert_eq!(f.decode(&[0xFF, 0xFF, 0xFF, 0xFF]), Err(FrameError::TooLong { len: 4_294_967_295, max: 100 }));
        assert_eq!(f.encode(&[0; 101], &mut Vec::new()), Err(FrameError::TooLong { len: 101, max: 100 }));
        assert_eq!(Framing::new(LengthHeader::Ascii4).decode(b"01x9abc"), Err(FrameError::BadHeader));

        // The header's own limit applies even when max_len is larger.
        let ascii = Framing { header: LengthHeader::Ascii4, max_len: 1_000_000 };
        assert_eq!(ascii.encode(&[0; 10_000], &mut Vec::new()), Err(FrameError::TooLong { len: 10_000, max: 9_999 }));
    }

    #[test]
    fn read_frame_refuses_a_huge_length_before_allocating() {
        let f = Framing { header: LengthHeader::Binary4, max_len: 100 };
        let err = f.read_frame(&mut &[0x7F, 0xFF, 0xFF, 0xFF][..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = f.read_frame(&mut &[0x00, 0x00, 0x00, 0x05, b'a'][..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "body shorter than the header promised");
    }
}
