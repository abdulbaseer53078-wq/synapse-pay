//! Redacted audit records of every ISO 8583 message to and from the host (Task 4.7).
//!
//! Each record carries the transaction_id, the message's hex dump with sensitive bytes replaced by `**`
//! (length prefixes kept, so offsets still match the wire), and a per-field view. Only an allowlist of
//! fields appears in clear; DE 2 is masked to its first 6 and last 4 digits; every other field, including
//! private and dialect-specific ones, is redacted by default. A message that doesn't parse can't be
//! redacted field by field, so its bytes are not recorded at all.
//!
//! Retention (RBI: 5 years) is the sink's job: ship these JSON lines to write-once storage.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use iso8583::{Bitmap, Dictionary, Encoding, FieldSpec};
use serde::Serialize;

/// Fields with no cardholder data, recorded in clear. Anything not listed is redacted.
pub const CLEAR_FIELDS: &[u8] = &[3, 4, 7, 11, 12, 13, 15, 18, 19, 22, 24, 25, 32, 37, 38, 39, 41, 42, 49, 70];
const PAN: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    pub at_unix_ms: u128,
    pub transaction_id: String,
    pub direction: Direction,
    pub length: usize,
    /// None if the message didn't parse.
    pub mti: Option<String>,
    /// The message bytes as uppercase hex, two characters per byte, with each redacted byte as `**`.
    /// None if the message didn't parse.
    pub hex: Option<String>,
    /// Field number → clear value, masked PAN, or `[redacted N bytes]`.
    pub fields: BTreeMap<u8, String>,
    /// Why the message couldn't be parsed; never contains its bytes.
    pub parse_error: Option<String>,
}

/// `400012******1234`: first 6 and last 4 digits, as PCI DSS allows. Shorter values are fully masked.
pub fn mask_pan(pan: &str) -> String {
    let n = pan.chars().count();
    if n < 13 {
        return "*".repeat(n);
    }
    let digits: Vec<char> = pan.chars().collect();
    format!("{}{}{}", digits[..6].iter().collect::<String>(), "*".repeat(n - 10),
            digits[n - 4..].iter().collect::<String>())
}

fn wire_len(encoding: Encoding, chars: usize) -> usize {
    match encoding {
        Encoding::Bcd => chars.div_ceil(2),
        _ => chars,
    }
}

/// Bytes of the length prefix in front of the field's value.
fn prefix_len(spec: FieldSpec) -> usize {
    match spec {
        FieldSpec::Llvar { prefix, .. } => wire_len(prefix, 2),
        FieldSpec::Lllvar { prefix, .. } => wire_len(prefix, 3),
        _ => 0,
    }
}

/// The audit record for one raw message (MTI onwards, without the TCP length header).
pub fn redact(raw: &[u8], dictionary: &Dictionary, transaction_id: &str, direction: Direction) -> AuditRecord {
    let at_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let mut record = AuditRecord {
        at_unix_ms, transaction_id: transaction_id.to_string(), direction, length: raw.len(),
        mti: None, hex: None, fields: BTreeMap::new(), parse_error: None,
    };
    match locate(raw, dictionary) {
        Ok((mti, spans)) => {
            let mut redacted = vec![false; raw.len()];
            for (field, value, start, end) in spans {
                let shown = if CLEAR_FIELDS.contains(&field) {
                    String::from_utf8_lossy(&value).into_owned()
                } else {
                    redacted[start..end].fill(true);
                    if field == PAN { mask_pan(&String::from_utf8_lossy(&value)) }
                    else { format!("[redacted {} bytes]", end - start) }
                };
                record.fields.insert(field, shown);
            }
            record.hex = Some(raw.iter().zip(&redacted)
                .map(|(b, &hide)| if hide { "**".to_string() } else { format!("{b:02X}") }).collect());
            record.mti = Some(mti);
        }
        Err(why) => record.parse_error = Some(why),
    }
    record
}

/// The MTI, and each field's (number, value, start, end), where start..end is its value's bytes on the wire.
#[allow(clippy::type_complexity)]
fn locate(raw: &[u8], d: &Dictionary) -> Result<(String, Vec<(u8, Vec<u8>, usize, usize)>), String> {
    let mti_len = wire_len(d.mti_encoding(), 4);
    let mti = iso8583::unpack(raw, d).map_err(|e| e.to_string())?.mti().to_string(); // validates the whole message
    let (bitmap, consumed) = Bitmap::parse_as(&raw[mti_len..], d.bitmap_encoding()).map_err(|e| e.to_string())?;
    let mut pos = mti_len + consumed;
    let mut spans = Vec::new();
    for field in bitmap.fields() {
        let spec = d.spec(field).ok_or("field not in dictionary")?;
        let (value, used) = d.read(field, &raw[pos..]).map_err(|e| e.to_string())?;
        spans.push((field, value.into_owned(), pos + prefix_len(spec), pos + used));
        pos += used;
    }
    Ok((mti, spans))
}

/// Where audit records go. Implementations must be durable: a record that can't be written must be an error.
pub trait AuditSink: Send + Sync {
    fn record(&self, record: &AuditRecord) -> io::Result<()>;
}

/// One JSON object per line, flushed per record.
///
/// shortcut: a blocking write under a mutex; move to a dedicated writer task if audit I/O shows up in latency.
pub struct JsonLines<W: Write + Send>(Mutex<W>);

impl<W: Write + Send> JsonLines<W> {
    pub fn new(writer: W) -> Self {
        Self(Mutex::new(writer))
    }

    pub fn into_inner(self) -> W {
        self.0.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<W: Write + Send> AuditSink for JsonLines<W> {
    fn record(&self, record: &AuditRecord) -> io::Result<()> {
        let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
        line.push(b'\n');
        let mut w = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        w.write_all(&line)?;
        w.flush()
    }
}
