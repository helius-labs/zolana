//! Transport decoding for the oracle boundary, and nothing else.
//!
//! Bytes cross as lowercase hex with no prefix, integers as decimal strings.
//! Decoding rejects anything it cannot read exactly; it never pads, truncates,
//! reorders, or substitutes a default, because every such repair would hide the
//! behavior the oracle exists to observe.

use num_bigint::BigUint;

pub const BAD_HEX: &str = "OracleMalformedHex";
pub const BAD_INTEGER: &str = "OracleMalformedInteger";

pub fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("odd hex length {}", value.len()));
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in bytes.chunks(2) {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

/// Decodes hex that must hold exactly `N` bytes. Callers use this where the Rust
/// signature under test takes `&[u8; N]`, so a shorter or longer input is
/// refused rather than resized.
pub fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex(value)?;
    if bytes.len() != N {
        return Err(format!("expected {N} bytes, read {}", bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("{value} is not a u64: {error}"))
}

pub fn decode_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|error| format!("{value} is not a usize: {error}"))
}

pub fn decode_i64(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|error| format!("{value} is not an i64: {error}"))
}

pub fn decode_biguint(value: &str) -> Result<BigUint, String> {
    value
        .parse::<BigUint>()
        .map_err(|error| format!("{value} is not an unsigned integer: {error}"))
}

fn nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        other => Err(format!(
            "{:?} is not a lowercase hex digit",
            char::from(other)
        )),
    }
}
