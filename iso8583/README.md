# iso8583

ISO 8583 message parsing (`unpack`) and building (`pack`) for the SynapsePay Host Connector. Each card
network or acquirer speaks its own dialect; a dialect is a JSON **dictionary** file, so supporting a new
host means writing a dictionary, not changing this crate.

## Install

The crate isn't published to a registry (`publish = false`). Depend on the git tag:

```toml
[dependencies]
iso8583 = { git = "https://github.com/abdulbaseer53078-wq/synapse-pay", tag = "iso8583-v1.0.0" }
```

## Use

```rust
use iso8583::{pack, unpack, Dictionary, Iso8583Message};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dictionary = Dictionary::from_json(r#"{
        "2": { "type": "LLVAR", "max_length": 19, "format": "n" },
        "4": { "type": "FIXED", "length": 12, "format": "n" },
        "required": { "0100": [2, 4] }
    }"#)?;

    // Build: set fields in any order; pack generates the bitmaps and length prefixes.
    let mut request = Iso8583Message::new("0100").expect("MTI is 4 digits");
    request.set(2, &b"4111111111111111"[..])?;
    request.set(4, &b"000000150000"[..])?;
    let wire: Vec<u8> = pack(&request, &dictionary)?;
    assert_eq!(&wire[..4], b"0100");

    // Parse: values borrow from `wire` (BCD fields are decoded to ASCII digits).
    let parsed = unpack(&wire, &dictionary)?;
    assert_eq!(parsed.mti(), "0100");
    assert_eq!(parsed.get_str(4), Some("000000150000"));
    Ok(())
}
```

A message is laid out as: **MTI** (4 ASCII digits), **bitmaps** (8 bytes each, binary; a second and third
follow when bit 1 of the previous one is set, for fields up to 192), then **each field present**, in
ascending field number, with its length prefix if it has one.

## Dictionary format

A JSON object. Each key is a field number (`"2"` to `"192"`, except the bitmap continuation bits 1, 65
and 129) mapping to that field's definition. One optional key, `"required"`, is not a field.

```json
{
  "2":  { "type": "LLVAR",  "max_length": 19,  "format": "n", "encoding": "bcd", "prefix": "bcd" },
  "4":  { "type": "FIXED",  "length": 12,      "format": "n", "encoding": "bcd" },
  "41": { "type": "FIXED",  "length": 8,       "format": "ans" },
  "55": { "type": "LLLVAR", "max_length": 255, "format": "b" },
  "required": { "0100": [2, 4, 41] }
}
```

### Field keys

| Key | Required | Values | Meaning |
| --- | --- | --- | --- |
| `type` | yes | `FIXED`, `LLVAR`, `LLLVAR` | `FIXED`: always `length` characters, no prefix. `LLVAR` / `LLLVAR`: a 2- / 3-digit length prefix, then that many characters. |
| `length` | `FIXED` only | 1 or more | Exact length. |
| `max_length` | `LLVAR`, `LLLVAR` | 1–99 (`LLVAR`), 1–999 (`LLLVAR`) | Longest value allowed. |
| `format` | yes | `n`, `an`, `ans`, `b` | Allowed characters: digits; letters and digits; printable ASCII (0x20–0x7E); any bytes. |
| `encoding` | no | `ascii` (default), `bcd` | How the value is carried. `bcd` packs two digits per byte and is only allowed with `format: n`. |
| `prefix` | no | `ascii` (default), `bcd` | How the `LLVAR`/`LLLVAR` length is carried: ASCII digits (2 or 3 bytes), or BCD (1 byte for LL, 2 for LLL). |

Lengths count **characters**: digits for `n` (even when BCD-packed), bytes for `b`. A BCD value with an odd
number of digits is left-padded with a `0` nibble (`840` → `08 40`).

Unknown keys are rejected, so a typo fails when the dictionary loads, not on live traffic.

### `required`

Maps an MTI to the fields a message with that MTI must carry. `pack` refuses to build a message missing one
(`PackError::MissingField`). Every listed field must be defined in the dictionary. MTIs not listed have no
required fields. `unpack` doesn't enforce it: a host may legitimately send fewer fields than you require when
sending.

### Dialect files

[`dialects/`](dialects/) holds `example.json`, `illustrative-rupay.json`, `illustrative-visa.json` and
`synthetic-host.json`. **None of them is a network's real specification** (RuPay's and Visa's are under NDA):
they follow public ISO 8583 conventions and exist to test the crate. Write the production dictionary from
your acquirer's interface spec and validate it against their certification messages.

## Errors and safety

- **Strict.** A field present in the bitmap but missing from the dictionary, a malformed or oversized
  length, a character outside the field's format, invalid BCD, or leftover bytes all fail the whole message:
  any of them means the parser has lost its alignment.
- **Descriptive.** Errors name the field and the rule, e.g.
  `FieldError::LengthExceeded { field: 2, max: 19, actual: 20 }` ("field 2 is 20 long, over its maximum of 19").
- **No card data in errors or logs.** Errors never include field values, and `Iso8583Message`'s `Debug`
  output shows only field numbers and lengths.

## Not supported in 1.0.0

BCD-encoded MTIs, message headers (e.g. Visa's), EBCDIC text, hex-ASCII bitmaps, and dialects that use DE 65
as a data field. Each would be an additive change.

## Stability

Semantic versioning from 1.0.0. Public enums are `#[non_exhaustive]`, so new error kinds, formats and
encodings can be added in minor releases: when matching on them, include a `_` arm.

## API docs

```sh
cargo doc --no-deps --open
```
