//! Tagged outcomes crossing the oracle boundary.
//!
//! Every exported function returns a JSON string holding either `ok` or `err`,
//! so the TypeScript side compares which arm was taken before it compares any
//! value. Rejections carry the Rust variant name plus its `Debug` payload,
//! matching the `{ code, details }` shape the committed fixtures already use.

use core::fmt::Debug;

use serde_json::{json, Value};

pub fn ok(value: Value) -> String {
    json!({ "ok": value }).to_string()
}

pub fn ok_hex(bytes: &[u8]) -> String {
    ok(Value::String(hex(bytes)))
}

pub fn ok_hex_list<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = &'a [u8; 32]>,
{
    ok(Value::Array(
        items
            .into_iter()
            .map(|item| Value::String(hex(item)))
            .collect(),
    ))
}

/// Rejection whose `code` is the Rust variant name and whose `details` is the
/// full `Debug` rendering, so a reader can tell `LeafDoesNotExist(3)` from
/// `LeafDoesNotExist(9)`.
pub fn err<E: Debug>(error: E) -> String {
    let details = format!("{error:?}");
    json!({ "err": { "code": variant_name(&details), "details": details } }).to_string()
}

/// Rejection raised by the wrapper rather than by a Rust call. Every use of this
/// is a place where a Rust signature was widened to accept a fuzzable input,
/// and the code names the constraint the signature carries.
pub fn err_boundary(code: &str, details: impl Into<String>) -> String {
    json!({ "err": { "code": code, "details": details.into() } }).to_string()
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Leading identifier of a `Debug` rendering: `Poseidon(InvalidWidth)` yields
/// `Poseidon`, `InvalidLevel { .. }` yields `InvalidLevel`.
fn variant_name(details: &str) -> &str {
    let end = details
        .find(|c: char| !c.is_alphanumeric() && c != '_')
        .unwrap_or(details.len());
    &details[..end]
}
