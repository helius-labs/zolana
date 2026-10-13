use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey as P256PublicKey};

use crate::{
    constants::{
        ED25519_PUBKEY_LEN, P256_PUBKEY_LEN, P256_UNCOMPRESSED_PUBKEY_LEN, PUBLIC_KEY_LEN,
    },
    error::KeypairError,
};

pub(crate) const SIGNATURE_TYPE_ED25519: u8 = 0x01;
pub(crate) const SIGNATURE_TYPE_PDA: u8 = 0x02;

/// The owner's encoding, not always a curve point: a PDA is off the Ed25519
/// curve and cannot sign. Prefix `0x00` is not a scheme: it only appears in
/// the all-zero padding owner. A `Pda` owner is identical to an `Ed25519` owner in
/// every public-data path; only the secret paths (client signing, role
/// derivation from a signing key) refuse it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Curve {
    Ed25519,
    Pda,
}

impl From<Curve> for u8 {
    fn from(value: Curve) -> Self {
        match value {
            Curve::Ed25519 => SIGNATURE_TYPE_ED25519,
            Curve::Pda => SIGNATURE_TYPE_PDA,
        }
    }
}

impl TryFrom<u8> for Curve {
    type Error = KeypairError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
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

    pub fn to_uncompressed(&self) -> Result<[u8; P256_UNCOMPRESSED_PUBKEY_LEN], KeypairError> {
        let encoded = self.to_p256()?.to_encoded_point(false);
        encoded
            .as_bytes()
            .try_into()
            .map_err(|_| KeypairError::InvalidPublicKey)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
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
    /// Byte 0 is no scheme, so [`Self::curve`] rejects it and
    /// [`Self::from_bytes`] refuses it; gate on [`Self::is_zero`] first.
    pub fn zeroed() -> Self {
        Self([0u8; PUBLIC_KEY_LEN])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; PUBLIC_KEY_LEN]
    }

    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<Self, KeypairError> {
        let (scheme, body) = bytes.split_first().ok_or(KeypairError::InvalidPublicKey)?;
        Curve::try_from(*scheme)?;
        if body
            .get(ED25519_PUBKEY_LEN..)
            .is_some_and(|tail| tail.iter().any(|byte| *byte != 0))
        {
            return Err(KeypairError::InvalidPublicKey);
        }
        Ok(Self(bytes))
    }

    pub fn curve(&self) -> Result<Curve, KeypairError> {
        Curve::try_from(self.0[0])
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
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
            Curve::Ed25519 => self.as_ed25519(),
            Curve::Pda => self.as_pda(),
        }
    }

    /// Owner identity over the 32-byte Solana owner tag,
    /// `hash_bytes_33(0x53 || tag)`.
    pub fn owner_proof_input_hash(&self) -> Result<[u8; 32], KeypairError> {
        let tag = self.confidential_view_tag()?;
        Ok(zolana_hasher::primitives::solana_owner_identity(&tag)?)
    }

    /// Verifies a [`crate::SigningKey::sign_message`] signature: ed25519 over
    /// the raw bytes. A PDA owner or malformed encoding verifies nothing.
    pub fn verify_message(&self, message: &[u8], sig: &[u8; 64]) -> bool {
        match self.curve() {
            Ok(Curve::Ed25519) => {
                use ed25519_dalek::Verifier;

                let Ok(bytes) = self.as_ed25519() else {
                    return false;
                };
                let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&bytes) else {
                    return false;
                };
                match ed25519_dalek::Signature::try_from(sig.as_slice()) {
                    Ok(parsed) => vk.verify(message, &parsed).is_ok(),
                    Err(_) => false,
                }
            }
            Ok(Curve::Pda) | Err(_) => false,
        }
    }
}
