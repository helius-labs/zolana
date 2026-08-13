use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey as P256PublicKey};

use crate::{
    constants::{ED25519_PUBKEY_LEN, P256_PUBKEY_LEN, PUBLIC_KEY_LEN},
    error::KeypairError,
};

pub(crate) const SIGNATURE_TYPE_P256: u8 = 0x00;
pub(crate) const SIGNATURE_TYPE_ED25519: u8 = 0x01;
pub(crate) const SIGNATURE_TYPE_PDA: u8 = 0x02;

/// The owner's encoding, not always a curve point: a PDA is off the Ed25519
/// curve and cannot sign. A `Pda` owner is identical to an `Ed25519` owner in
/// every public-data path; only the secret paths (client signing, role
/// derivation from a signing key) refuse it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Curve {
    P256,
    Ed25519,
    Pda,
}

impl From<Curve> for u8 {
    fn from(value: Curve) -> Self {
        match value {
            Curve::P256 => SIGNATURE_TYPE_P256,
            Curve::Ed25519 => SIGNATURE_TYPE_ED25519,
            Curve::Pda => SIGNATURE_TYPE_PDA,
        }
    }
}

impl TryFrom<u8> for Curve {
    type Error = KeypairError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            SIGNATURE_TYPE_P256 => Ok(Curve::P256),
            SIGNATURE_TYPE_ED25519 => Ok(Curve::Ed25519),
            SIGNATURE_TYPE_PDA => Ok(Curve::Pda),
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
        bytes[0] = u8::from(Curve::P256);
        bytes[1..].copy_from_slice(pubkey.as_bytes());
        Self(bytes)
    }

    pub fn from_ed25519(pubkey: &[u8; ED25519_PUBKEY_LEN]) -> Self {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes[0] = u8::from(Curve::Ed25519);
        bytes[1..1 + ED25519_PUBKEY_LEN].copy_from_slice(pubkey);
        Self(bytes)
    }

    pub fn from_pda(pda: &solana_address::Address) -> Self {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes[0] = u8::from(Curve::Pda);
        bytes[1..1 + ED25519_PUBKEY_LEN].copy_from_slice(pda.as_array());
        Self(bytes)
    }

    /// All-zero owner of a padding (dummy) UTXO. `owner = 0` is permanently
    /// unspendable, so a real input never has it; it is the canonical dummy marker.
    /// Byte 0 reads as `SIGNATURE_TYPE_P256`, so this value must never reach
    /// [`Self::curve`]; gate on [`Self::is_zero`] first.
    pub fn zeroed() -> Self {
        Self([0u8; PUBLIC_KEY_LEN])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; PUBLIC_KEY_LEN]
    }

    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<Self, KeypairError> {
        match Curve::try_from(bytes[0])? {
            Curve::P256 => {
                let mut body = [0u8; P256_PUBKEY_LEN];
                body.copy_from_slice(&bytes[1..]);
                P256Pubkey::from_bytes(body)?;
                Ok(Self(bytes))
            }
            Curve::Ed25519 | Curve::Pda => {
                if bytes[PUBLIC_KEY_LEN - 1] != 0 {
                    return Err(KeypairError::InvalidPublicKey);
                }
                Ok(Self(bytes))
            }
        }
    }

    pub fn curve(&self) -> Result<Curve, KeypairError> {
        Curve::try_from(self.0[0])
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn as_p256(&self) -> Result<P256Pubkey, KeypairError> {
        if self.curve()? != Curve::P256 {
            return Err(KeypairError::InvalidSignatureType(self.0[0]));
        }
        let mut body = [0u8; P256_PUBKEY_LEN];
        body.copy_from_slice(&self.0[1..]);
        P256Pubkey::from_bytes(body)
    }

    pub fn as_ed25519(&self) -> Result<[u8; ED25519_PUBKEY_LEN], KeypairError> {
        if self.curve()? != Curve::Ed25519 {
            return Err(KeypairError::InvalidSignatureType(self.0[0]));
        }
        let mut body = [0u8; ED25519_PUBKEY_LEN];
        body.copy_from_slice(&self.0[1..1 + ED25519_PUBKEY_LEN]);
        Ok(body)
    }

    pub fn as_pda(&self) -> Result<[u8; ED25519_PUBKEY_LEN], KeypairError> {
        if self.curve()? != Curve::Pda {
            return Err(KeypairError::InvalidSignatureType(self.0[0]));
        }
        let mut body = [0u8; ED25519_PUBKEY_LEN];
        body.copy_from_slice(&self.0[1..1 + ED25519_PUBKEY_LEN]);
        Ok(body)
    }

    pub fn confidential_view_tag(&self) -> Result<[u8; 32], KeypairError> {
        match self.curve()? {
            Curve::P256 => Ok(self.as_p256()?.x()),
            Curve::Ed25519 => self.as_ed25519(),
            Curve::Pda => self.as_pda(),
        }
    }

    /// Owner-identity proof-input hash over the fixed 32-byte owner tag. P256
    /// parity is excluded because it is carried in encrypted owner data.
    pub fn owner_proof_input_hash(&self) -> Result<[u8; 32], KeypairError> {
        Ok(zolana_hasher::primitives::hash_bytes(
            &self.confidential_view_tag()?,
        )?)
    }
}
