use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey as P256PublicKey;

use crate::constants::{ED25519_PUBKEY_LEN, P256_PUBKEY_LEN, PUBLIC_KEY_LEN};
use crate::error::Error;

pub(crate) const SIGNATURE_TYPE_P256: u8 = 0x00;
pub(crate) const SIGNATURE_TYPE_ED25519: u8 = 0x01;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignatureType {
    P256,
    Ed25519,
}

impl SignatureType {
    pub fn prefix(self) -> u8 {
        match self {
            SignatureType::P256 => SIGNATURE_TYPE_P256,
            SignatureType::Ed25519 => SIGNATURE_TYPE_ED25519,
        }
    }

    pub fn from_prefix(prefix: u8) -> Result<Self, Error> {
        match prefix {
            SIGNATURE_TYPE_P256 => Ok(SignatureType::P256),
            SIGNATURE_TYPE_ED25519 => Ok(SignatureType::Ed25519),
            other => Err(Error::InvalidSignatureType(other)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct P256Pubkey([u8; P256_PUBKEY_LEN]);

impl P256Pubkey {
    pub fn from_bytes(bytes: [u8; P256_PUBKEY_LEN]) -> Result<Self, Error> {
        P256PublicKey::from_sec1_bytes(&bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn from_p256(pubkey: &P256PublicKey) -> Self {
        let encoded = pubkey.to_encoded_point(true);
        let mut bytes = [0u8; P256_PUBKEY_LEN];
        bytes.copy_from_slice(encoded.as_bytes());
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; P256_PUBKEY_LEN] {
        &self.0
    }

    pub fn x(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        x.copy_from_slice(&self.0[1..]);
        x
    }

    pub fn y_is_odd(&self) -> bool {
        self.0[0] == 0x03
    }

    pub fn to_p256(&self) -> P256PublicKey {
        P256PublicKey::from_sec1_bytes(&self.0).expect("validated on construction")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn from_p256(pubkey: &P256Pubkey) -> Self {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes[0] = SignatureType::P256.prefix();
        bytes[1..].copy_from_slice(pubkey.as_bytes());
        Self(bytes)
    }

    pub fn from_ed25519(pubkey: &[u8; ED25519_PUBKEY_LEN]) -> Self {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes[0] = SignatureType::Ed25519.prefix();
        bytes[1..1 + ED25519_PUBKEY_LEN].copy_from_slice(pubkey);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<Self, Error> {
        match SignatureType::from_prefix(bytes[0])? {
            SignatureType::P256 => {
                let mut body = [0u8; P256_PUBKEY_LEN];
                body.copy_from_slice(&bytes[1..]);
                P256Pubkey::from_bytes(body)?;
                Ok(Self(bytes))
            }
            SignatureType::Ed25519 => Ok(Self(bytes)),
        }
    }

    pub fn signature_type(&self) -> SignatureType {
        SignatureType::from_prefix(self.0[0])
            .expect("public key has a validated signature-type prefix")
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn as_p256(&self) -> Result<P256Pubkey, Error> {
        if self.signature_type() != SignatureType::P256 {
            return Err(Error::InvalidSignatureType(self.0[0]));
        }
        let mut body = [0u8; P256_PUBKEY_LEN];
        body.copy_from_slice(&self.0[1..]);
        P256Pubkey::from_bytes(body)
    }

    pub fn as_ed25519(&self) -> Result<[u8; ED25519_PUBKEY_LEN], Error> {
        if self.signature_type() != SignatureType::Ed25519 {
            return Err(Error::InvalidSignatureType(self.0[0]));
        }
        let mut body = [0u8; ED25519_PUBKEY_LEN];
        body.copy_from_slice(&self.0[1..1 + ED25519_PUBKEY_LEN]);
        Ok(body)
    }
}
