use crate::{
    constants::{ED25519_PUBKEY_LEN, PUBLIC_KEY_LEN},
    error::KeypairError,
};

pub(crate) const SIGNATURE_TYPE_ED25519: u8 = 0x01;
pub(crate) const SIGNATURE_TYPE_PDA: u8 = 0x02;

/// Tag byte of a synthetic [`PublicKey`] that carries a precomputed owner
/// identity instead of a key (see [`PublicKey::from_owner_identity`]). It is not
/// a [`Curve`], so every key path ([`PublicKey::curve`], signing, byte
/// validation) rejects it; only [`PublicKey::owner_proof_input_hash`] reads it.
pub(crate) const PRECOMPUTED_OWNER_IDENTITY_TYPE: u8 = 0xFF;

/// The owner's encoding, not always a curve point: a PDA is off the Ed25519
/// curve and cannot sign. A `Pda` owner is identical to an `Ed25519` owner in
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
#[cfg_attr(feature = "tsify", derive(tsify::Tsify), tsify(type = "Uint8Array"))]
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

    /// A synthetic key for an owner known only by its owner identity (the
    /// [`Self::owner_proof_input_hash`] of its real key), such as a transfer
    /// recipient or vault owner read from a policy-ring account that stores the
    /// identity rather than the key. Owner hashes, UTXO hashes and the prover's
    /// owner assembly consume only the identity, so such an owner hashes and
    /// proves exactly as its real key would. It cannot sign, has no view tag, and
    /// is never serialized.
    pub fn from_owner_identity(identity: [u8; 32]) -> Self {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes[0] = PRECOMPUTED_OWNER_IDENTITY_TYPE;
        bytes[1..1 + 32].copy_from_slice(&identity);
        Self(bytes)
    }

    /// True for a key built by [`Self::from_owner_identity`]; such a key must be
    /// consumed only through [`Self::owner_proof_input_hash`].
    pub fn is_precomputed_owner_identity(&self) -> bool {
        self.0[0] == PRECOMPUTED_OWNER_IDENTITY_TYPE
    }

    /// All-zero owner of a padding (dummy) UTXO. `owner = 0` is permanently
    /// unspendable, so a real input never has it; it is the canonical dummy marker.
    /// Byte 0 names no owner scheme, so [`Self::curve`] rejects this value;
    /// gate on [`Self::is_zero`] first.
    pub fn zeroed() -> Self {
        Self([0u8; PUBLIC_KEY_LEN])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; PUBLIC_KEY_LEN]
    }

    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<Self, KeypairError> {
        Curve::try_from(bytes[0])?;
        if bytes[PUBLIC_KEY_LEN - 1] != 0 {
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

    /// Commits the Solana owner identity with its domain tag.
    pub fn owner_proof_input_hash(&self) -> Result<[u8; 32], KeypairError> {
        if self.is_precomputed_owner_identity() {
            let mut identity = [0u8; 32];
            identity.copy_from_slice(&self.0[1..1 + 32]);
            return Ok(identity);
        }
        Ok(zolana_hasher::primitives::solana_owner_identity(
            &self.confidential_view_tag()?,
        )?)
    }

    /// A PDA or unknown encoding verifies nothing.
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

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: [u8; PUBLIC_KEY_LEN] = serde_bytes::deserialize(deserializer)?;
        if bytes == [0u8; PUBLIC_KEY_LEN] {
            return Ok(Self::zeroed());
        }
        Self::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precomputed_owner_identity_hashes_as_the_identity() {
        let mut identity = [0u8; 32];
        identity[31] = 42;
        let key = PublicKey::from_owner_identity(identity);
        assert!(key.is_precomputed_owner_identity());
        assert_eq!(key.owner_proof_input_hash().unwrap(), identity);
        assert_eq!(
            key.curve(),
            Err(KeypairError::InvalidSignatureType(
                PRECOMPUTED_OWNER_IDENTITY_TYPE
            ))
        );
        assert!(key.confidential_view_tag().is_err());
    }

    #[test]
    fn real_keys_are_not_precomputed_owner_identities() {
        let pda = PublicKey::from_pda(&solana_address::Address::new_from_array([5u8; 32]));
        assert!(!pda.is_precomputed_owner_identity());
        let identity = pda.owner_proof_input_hash().unwrap();
        assert_eq!(
            PublicKey::from_owner_identity(identity)
                .owner_proof_input_hash()
                .unwrap(),
            identity
        );
    }
}
