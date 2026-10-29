//! Circuit gates and the metadata describing them in a deployed program.
//!
//! Export an encoded [`CircuitFeature`] as a public static with an
//! `export_name`, as with VK setup markers. Use that same descriptor to authorize
//! proofs: the presence of a verifying key alone does not enable a feature.
//! Do not add `#[used]`: its GNU-retain ELF flags are incompatible with SBF.
#![no_std]

#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
mod parse;
#[cfg(feature = "std")]
pub use parse::{find_features, FeatureInfo, ParseError};

/// Features are defined here; programs forward their Cargo features to this
/// crate rather than maintaining a second set of enabled-state checks.
pub mod features;

pub const BEGIN: &[u8] = b"=======BEGIN SPR CIRCUIT FEATURE V1=======\0";
pub const END: &[u8] = b"=======END SPR CIRCUIT FEATURE V1=======\0";
const NAME: &[u8] = b"name\0";
const ENABLED: &[u8] = b"enabled\0";
const HASH: &[u8] = b"proving_key_sha256\0";

#[derive(Clone, Copy, Debug)]
pub struct CircuitFeature {
    pub name: &'static str,
    pub enabled: bool,
    pub proving_key_sha256s: &'static [[u8; 32]],
}

impl CircuitFeature {
    pub fn allows(&self, proving_key_sha256: &[u8; 32]) -> bool {
        self.enabled && self.proving_key_sha256s.contains(proving_key_sha256)
    }

    pub const fn encoded_len(&self) -> usize {
        BEGIN.len()
            + NAME.len()
            + self.name.len()
            + 1
            + ENABLED.len()
            + if self.enabled { 5 } else { 6 }
            + self.proving_key_sha256s.len() * (HASH.len() + 65)
            + END.len()
    }

    /// Encode at compile time; `N` must equal [`Self::encoded_len`].
    pub const fn encode<const N: usize>(&self) -> [u8; N] {
        assert!(N == self.encoded_len(), "incorrect feature marker length");
        assert!(!self.name.is_empty(), "empty circuit feature name");
        assert!(!self.proving_key_sha256s.is_empty(), "feature has no keys");
        let mut encoded = [0; N];
        let mut offset = 0;
        write(&mut encoded, &mut offset, BEGIN);
        write(&mut encoded, &mut offset, NAME);
        write(&mut encoded, &mut offset, self.name.as_bytes());
        write(&mut encoded, &mut offset, b"\0");
        write(&mut encoded, &mut offset, ENABLED);
        write(
            &mut encoded,
            &mut offset,
            if self.enabled { b"true\0" } else { b"false\0" },
        );
        let mut keys = self.proving_key_sha256s;
        while let Some((hash, rest)) = keys.split_first() {
            write(&mut encoded, &mut offset, HASH);
            let mut bytes: &[u8] = hash;
            while let Some((byte, rest)) = bytes.split_first() {
                write(
                    &mut encoded,
                    &mut offset,
                    &[hex_digit(*byte >> 4), hex_digit(*byte & 15)],
                );
                bytes = rest;
            }
            write(&mut encoded, &mut offset, b"\0");
            keys = rest;
        }
        write(&mut encoded, &mut offset, END);
        encoded
    }
}

const fn hex_digit(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'a' + value - 10
    }
}

const fn write<const N: usize>(out: &mut [u8; N], offset: &mut usize, mut bytes: &[u8]) {
    let (_, mut remaining) = out.split_at_mut(*offset);
    while let Some((byte, rest)) = bytes.split_first() {
        match remaining.split_first_mut() {
            Some((slot, tail)) => {
                *slot = *byte;
                remaining = tail;
            }
            None => panic!("feature marker overflow"),
        }
        *offset += 1;
        bytes = rest;
    }
}

/// Select a family from generated key metadata without copying its hashes.
/// A changed family size fails compilation when used in a constant.
pub const fn hashes_with_prefix<const N: usize>(
    mut keys: &[(&str, [u8; 32])],
    prefix: &str,
) -> [[u8; 32]; N] {
    let mut selected = [[0; 32]; N];
    let mut count = 0;
    while let Some(((name, hash), rest)) = keys.split_first() {
        if starts_with(name.as_bytes(), prefix.as_bytes()) {
            let (_, remaining) = selected.split_at_mut(count);
            match remaining.split_first_mut() {
                Some((slot, _)) => *slot = *hash,
                None => panic!("too many circuit feature keys"),
            }
            count += 1;
        }
        keys = rest;
    }
    assert!(count == N, "missing circuit feature keys");
    selected
}

const fn starts_with(mut bytes: &[u8], mut prefix: &[u8]) -> bool {
    while let Some((expected, rest)) = prefix.split_first() {
        match bytes.split_first() {
            Some((actual, tail)) if *actual == *expected => bytes = tail,
            _ => return false,
        }
        prefix = rest;
    }
    true
}
