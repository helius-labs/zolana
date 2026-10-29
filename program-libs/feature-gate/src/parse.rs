use std::{
    fmt,
    string::{String, ToString},
    vec::Vec,
};

use crate::{BEGIN, END};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureInfo {
    pub name: String,
    pub enabled: bool,
    pub proving_key_sha256s: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub reason: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "circuit feature marker at {}: {}",
            self.offset, self.reason
        )
    }
}
impl std::error::Error for ParseError {}

/// Read exported markers from an ELF or a deployed program's bytes.
/// Missing metadata returns an empty list, never an inferred feature state.
pub fn find_features(binary: &[u8]) -> Result<Vec<FeatureInfo>, ParseError> {
    let mut features: Vec<FeatureInfo> = Vec::new();
    let mut offset = 0;
    while let Some(start) = binary.get(offset..).and_then(|bytes| find(bytes, BEGIN)) {
        let start = offset + start;
        let error = |reason| ParseError {
            offset: start,
            reason,
        };
        let body_start = start + BEGIN.len();
        let rest = binary.get(body_start..).ok_or(error("missing body"))?;
        let length = find(rest, END).ok_or(error("unterminated marker"))?;
        let body = rest.get(..length).ok_or(error("missing body"))?;
        let text = core::str::from_utf8(body).map_err(|_| error("not UTF-8"))?;
        let mut parts = text.split('\0');
        if parts.next() != Some("name") {
            return Err(error("missing name"));
        }
        let name = parts.next().ok_or(error("missing name"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(error("invalid feature name"));
        }
        if features.iter().any(|feature| feature.name == name) {
            return Err(error("duplicate feature name"));
        }
        if parts.next() != Some("enabled") {
            return Err(error("missing enabled flag"));
        }
        let enabled = match parts.next() {
            Some("true") => true,
            Some("false") => false,
            _ => return Err(error("invalid enabled flag")),
        };
        let mut hashes = Vec::new();
        loop {
            match parts.next() {
                Some("") if parts.next().is_none() => break,
                Some("proving_key_sha256") => {
                    let text = parts.next().ok_or(error("missing proving key hash"))?;
                    if text.len() != 64 {
                        return Err(error("invalid proving key hash"));
                    }
                    let mut hash = [0; 32];
                    for (byte, digits) in hash.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
                        let digits = core::str::from_utf8(digits)
                            .map_err(|_| error("invalid proving key hash"))?;
                        *byte = u8::from_str_radix(digits, 16)
                            .map_err(|_| error("invalid proving key hash"))?;
                    }
                    if hashes.contains(&hash) {
                        return Err(error("duplicate proving key hash"));
                    }
                    hashes.push(hash);
                }
                _ => return Err(error("unexpected marker field")),
            }
        }
        if hashes.is_empty() {
            return Err(error("feature has no keys"));
        }
        features.push(FeatureInfo {
            name: name.to_string(),
            enabled,
            proving_key_sha256s: hashes,
        });
        offset = body_start + length + END.len();
    }
    Ok(features)
}

fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
}
