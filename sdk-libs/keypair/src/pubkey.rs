use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey as P256PublicKey;

use crate::constants::{ED25519_PUBKEY_LEN, P256_PUBKEY_LEN, PUBLIC_KEY_LEN};
use crate::error::KeypairError;

pub(crate) const SIGNATURE_TYPE_P256: u8 = 0x00;
pub(crate) const SIGNATURE_TYPE_ED25519: u8 = 0x01;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignatureType {
    P256,
    Ed25519,
}

impl From<SignatureType> for u8 {
    fn from(value: SignatureType) -> Self {
        match value {
            SignatureType::P256 => SIGNATURE_TYPE_P256,
            SignatureType::Ed25519 => SIGNATURE_TYPE_ED25519,
        }
    }
}

impl TryFrom<u8> for SignatureType {
    type Error = KeypairError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            SIGNATURE_TYPE_P256 => Ok(SignatureType::P256),
            SIGNATURE_TYPE_ED25519 => Ok(SignatureType::Ed25519),
            other => Err(KeypairError::InvalidSignatureType(other)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct P256Pubkey([u8; P256_PUBKEY_LEN]);

impl P256Pubkey {
    pub fn from_bytes(bytes: [u8; P256_PUBKEY_LEN]) -> Result<Self, KeypairError> {
        P256PublicKey::from_sec1_bytes(&bytes).map_err(|_| KeypairError::InvalidPublicKey)?;
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

    pub fn to_p256(&self) -> Result<P256PublicKey, KeypairError> {
        P256PublicKey::from_sec1_bytes(&self.0).map_err(|_| KeypairError::InvalidPublicKey)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn from_p256(pubkey: &P256Pubkey) -> Self {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes[0] = u8::from(SignatureType::P256);
        bytes[1..].copy_from_slice(pubkey.as_bytes());
        Self(bytes)
    }

    pub fn from_ed25519(pubkey: &[u8; ED25519_PUBKEY_LEN]) -> Self {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes[0] = u8::from(SignatureType::Ed25519);
        bytes[1..1 + ED25519_PUBKEY_LEN].copy_from_slice(pubkey);
        Self(bytes)
    }

    /// All-zero owner of a padding (dummy) UTXO. `owner = 0` is permanently
    /// unspendable, so a real input never has it; it is the canonical dummy marker.
    /// Byte 0 reads as `SIGNATURE_TYPE_P256`, so this value must never reach
    /// [`Self::signature_type`]; gate on [`Self::is_zero`] first.
    pub fn zeroed() -> Self {
        Self([0u8; PUBLIC_KEY_LEN])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; PUBLIC_KEY_LEN]
    }

    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<Self, KeypairError> {
        match SignatureType::try_from(bytes[0])? {
            SignatureType::P256 => {
                let mut body = [0u8; P256_PUBKEY_LEN];
                body.copy_from_slice(&bytes[1..]);
                P256Pubkey::from_bytes(body)?;
                Ok(Self(bytes))
            }
            SignatureType::Ed25519 => {
                if bytes[PUBLIC_KEY_LEN - 1] != 0 {
                    return Err(KeypairError::InvalidPublicKey);
                }
                Ok(Self(bytes))
            }
        }
    }

    pub fn signature_type(&self) -> Result<SignatureType, KeypairError> {
        SignatureType::try_from(self.0[0])
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn as_p256(&self) -> Result<P256Pubkey, KeypairError> {
        if self.signature_type()? != SignatureType::P256 {
            return Err(KeypairError::InvalidSignatureType(self.0[0]));
        }
        let mut body = [0u8; P256_PUBKEY_LEN];
        body.copy_from_slice(&self.0[1..]);
        P256Pubkey::from_bytes(body)
    }

    pub fn as_ed25519(&self) -> Result<[u8; ED25519_PUBKEY_LEN], KeypairError> {
        if self.signature_type()? != SignatureType::Ed25519 {
            return Err(KeypairError::InvalidSignatureType(self.0[0]));
        }
        let mut body = [0u8; ED25519_PUBKEY_LEN];
        body.copy_from_slice(&self.0[1..1 + ED25519_PUBKEY_LEN]);
        Ok(body)
    }

    pub fn hash(&self) -> Result<[u8; 32], KeypairError> {
        match self.signature_type()? {
            SignatureType::P256 => {
                let p = self.as_p256()?;
                let x_hash = crate::hash::hash_field(&p.x())?;
                crate::hash::poseidon(&[&crate::hash::bool_fe(p.y_is_odd()), &x_hash])
            }
            SignatureType::Ed25519 => crate::hash::hash_field(&self.as_ed25519()?),
        }
    }
}
