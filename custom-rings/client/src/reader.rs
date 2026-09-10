use std::{fmt, str::FromStr};

use curve25519_dalek::edwards::CompressedEdwardsY;
pub use custom_ring_interface::READ_ACCESS_RECORD_PDA_SEED;
use custom_ring_interface::{READER_KEY_ED25519, READER_KEY_P256};
use sha2::{Digest, Sha256};
use solana_address::Address;
use thiserror::Error;
use zolana_keypair::{P256Pubkey, PublicKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReaderKey {
    Ed25519(Ed25519ReaderKey),
    P256(P256ReaderKey),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ed25519ReaderKey(Address);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct P256ReaderKey(P256Pubkey);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ReaderKeyError {
    #[error("reader key is not a base58 Ed25519 key or hexadecimal P256 key")]
    Text,
    #[error("reader key tag names a scheme that cannot sign a read")]
    Scheme,
    #[error("reader key body is not a valid key for its scheme")]
    Body,
}

impl ReaderKey {
    pub fn ed25519(address: Address) -> Result<Self, ReaderKeyError> {
        Ed25519ReaderKey::try_from(address).map(Self::Ed25519)
    }

    pub fn p256(key: P256Pubkey) -> Result<Self, ReaderKeyError> {
        P256ReaderKey::try_from(key).map(Self::P256)
    }

    pub fn to_bytes(self) -> [u8; 34] {
        match self {
            Self::Ed25519(key) => *PublicKey::from_ed25519(key.address().as_array()).as_bytes(),
            Self::P256(key) => *PublicKey::from_p256(&key.pubkey()).as_bytes(),
        }
    }

    pub fn from_bytes(bytes: [u8; 34]) -> Result<Self, ReaderKeyError> {
        let key = PublicKey::from_bytes(bytes).map_err(|_| ReaderKeyError::Body)?;
        match bytes[0] {
            READER_KEY_ED25519 => {
                let body = key.as_ed25519().map_err(|_| ReaderKeyError::Body)?;
                Self::ed25519(Address::new_from_array(body))
            }
            READER_KEY_P256 => Self::p256(key.as_p256().map_err(|_| ReaderKeyError::Body)?),
            _ => Err(ReaderKeyError::Scheme),
        }
    }

    pub fn entry_address(self, ring: &Address) -> Address {
        let seed_hash: [u8; 32] = Sha256::digest(self.to_bytes()).into();
        Address::find_program_address(&[READ_ACCESS_RECORD_PDA_SEED, &seed_hash], ring).0
    }
}

impl Ed25519ReaderKey {
    pub fn address(self) -> Address {
        self.0
    }
}

impl TryFrom<Address> for Ed25519ReaderKey {
    type Error = ReaderKeyError;

    fn try_from(address: Address) -> Result<Self, Self::Error> {
        let body = *address.as_array();
        CompressedEdwardsY(body)
            .decompress()
            .filter(|point| {
                point.compress().to_bytes() == body
                    && point.is_torsion_free()
                    && !point.is_small_order()
            })
            .map(|_| Self(address))
            .ok_or(ReaderKeyError::Body)
    }
}

impl P256ReaderKey {
    pub fn pubkey(self) -> P256Pubkey {
        self.0
    }
}

impl TryFrom<P256Pubkey> for P256ReaderKey {
    type Error = ReaderKeyError;

    fn try_from(key: P256Pubkey) -> Result<Self, Self::Error> {
        (!zolana_interface::is_reserved_p256_derivation_point(key.as_bytes()))
            .then_some(Self(key))
            .ok_or(ReaderKeyError::Body)
    }
}

impl FromStr for ReaderKey {
    type Err = ReaderKeyError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = text.parse::<Address>() {
            return Self::ed25519(address).map_err(|_| ReaderKeyError::Text);
        }
        let bytes: [u8; 33] = hex::decode(text)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(ReaderKeyError::Text)?;
        let key = P256Pubkey::from_bytes(bytes).map_err(|_| ReaderKeyError::Text)?;
        Self::p256(key).map_err(|_| ReaderKeyError::Text)
    }
}

impl fmt::Display for ReaderKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(key) => key.address().fmt(formatter),
            Self::P256(key) => formatter.write_str(&hex::encode(key.pubkey().as_bytes())),
        }
    }
}
