//! Keys a ring authority delegates ring-scope reads to.

use std::{fmt, str::FromStr};

use sha2::{Digest, Sha256};
use solana_address::Address;
use thiserror::Error;
use zolana_keypair::{P256Pubkey, PublicKey};

/// Seed of a ring's reader records. Mirrors the custom ring program.
pub const READER_RECORD_PDA_SEED: &[u8] = b"reader";

const TAG_P256: u8 = 0x00;
const TAG_ED25519: u8 = 0x01;

/// A Solana wallet key or a P-256 key such as a passkey. Text form is base58
/// for ed25519 and 66 hex characters (SEC1 compressed) for P-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReaderKey {
    Ed25519(Address),
    P256(P256Pubkey),
}

#[derive(Debug, Error)]
#[error("reader key is neither a base58 ed25519 key nor a 66-hex SEC1 P-256 key")]
pub struct ReaderKeyParseError;

impl ReaderKey {
    /// The protocol's 34-byte scheme-tagged layout, what the record stores.
    pub fn to_bytes(self) -> [u8; 34] {
        match self {
            Self::Ed25519(address) => *PublicKey::from_ed25519(address.as_array()).as_bytes(),
            Self::P256(pubkey) => *PublicKey::from_p256(&pubkey).as_bytes(),
        }
    }

    /// `None` for a PDA tag or a malformed body: neither can sign a read.
    pub fn from_bytes(bytes: [u8; 34]) -> Option<Self> {
        let key = PublicKey::from_bytes(bytes).ok()?;
        match bytes[0] {
            TAG_ED25519 => Some(Self::Ed25519(Address::new_from_array(
                key.as_ed25519().ok()?,
            ))),
            TAG_P256 => Some(Self::P256(key.as_p256().ok()?)),
            _ => None,
        }
    }

    /// The reader record under `ring`. The 34-byte key exceeds one seed, so
    /// the record is keyed by its SHA-256.
    pub fn record_address(self, ring: &Address) -> Address {
        let seed_hash: [u8; 32] = Sha256::digest(self.to_bytes()).into();
        Address::find_program_address(&[READER_RECORD_PDA_SEED, &seed_hash], ring).0
    }
}

impl FromStr for ReaderKey {
    type Err = ReaderKeyParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = text.parse::<Address>() {
            return Ok(Self::Ed25519(address));
        }
        let bytes: [u8; 33] = hex::decode(text)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(ReaderKeyParseError)?;
        P256Pubkey::from_bytes(bytes)
            .map(Self::P256)
            .map_err(|_| ReaderKeyParseError)
    }
}

impl fmt::Display for ReaderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(address) => address.fmt(f),
            Self::P256(pubkey) => f.write_str(&hex::encode(pubkey.as_bytes())),
        }
    }
}
