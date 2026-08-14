use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as DalekSigningKey};
use p256::{
    ecdsa::{
        signature::hazmat::PrehashSigner, Signature as EcdsaSig, SigningKey as EcdsaSigningKey,
    },
    SecretKey,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    derivation,
    error::KeypairError,
    pubkey::{Curve, P256Pubkey, PublicKey},
};

#[derive(Clone)]
enum SigningKeyInner {
    P256(EcdsaSigningKey),
    Ed25519(DalekSigningKey),
}

#[derive(Clone)]
pub struct SigningKey {
    inner: SigningKeyInner,
}

impl SigningKey {
    pub fn new_p256() -> Self {
        Self {
            inner: SigningKeyInner::P256(EcdsaSigningKey::random(&mut OsRng)),
        }
    }

    /// A fresh random ed25519 key. Mirrors [`Self::new_p256`] for callers that
    /// need a throwaway key on the ed25519 rail; the secret bytes are zeroized
    /// once copied into the dalek key.
    pub fn new_ed25519() -> Self {
        let mut secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(secret.as_mut());
        Self {
            inner: SigningKeyInner::Ed25519(DalekSigningKey::from_bytes(&secret)),
        }
    }
    pub fn from_p256_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let secret =
            EcdsaSigningKey::from_slice(bytes).map_err(|_| KeypairError::InvalidSecretKey)?;
        Ok(Self {
            inner: SigningKeyInner::P256(secret),
        })
    }

    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: SigningKeyInner::Ed25519(DalekSigningKey::from_bytes(bytes)),
        }
    }

    pub fn curve(&self) -> Curve {
        match self.inner {
            SigningKeyInner::P256(_) => Curve::P256,
            SigningKeyInner::Ed25519(_) => Curve::Ed25519,
        }
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        match &self.inner {
            SigningKeyInner::P256(sk) => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&sk.to_bytes());
                Zeroizing::new(out)
            }
            SigningKeyInner::Ed25519(sk) => Zeroizing::new(*sk.as_bytes()),
        }
    }

    pub fn pubkey(&self) -> PublicKey {
        match &self.inner {
            SigningKeyInner::P256(sk) => {
                PublicKey::from_p256(&P256Pubkey::from_p256(&sk.verifying_key().into()))
            }
            SigningKeyInner::Ed25519(sk) => {
                let vk = sk.verifying_key();
                PublicKey::from_ed25519(vk.as_bytes())
            }
        }
    }

    /// The scheme's native message signature: ed25519 over the raw bytes
    /// (RFC 8032), P256 as ECDSA over `SHA-256(message)` normalized to low-S,
    /// matching Solana's secp256r1 precompile.
    ///
    /// The derivation-input guard is meaningful on the ed25519 arm, where
    /// signing the derivation message would yield the derivation seed. The
    /// P-256 rail's seed is `ECDH(sk, P_derive)`, guarded by the
    /// committed-point check in [`Self::ecdh`].
    pub fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput);
        }
        match &self.inner {
            SigningKeyInner::P256(sk) => {
                let digest = Sha256::digest(message);
                let signature: EcdsaSig = sk
                    .sign_prehash(&digest)
                    .map_err(|_| KeypairError::SigningFailed)?;
                let signature = signature.normalize_s().unwrap_or(signature);
                let mut out = [0u8; 64];
                out.copy_from_slice(&signature.to_bytes());
                Ok(out)
            }
            SigningKeyInner::Ed25519(sk) => Ok(sk.sign(message).to_bytes()),
        }
    }

    /// ECDSA over a caller-supplied digest, the proof path: the transfer proof
    /// verifies the signature against `SHA-256(private_tx_hash)`. P-256 rail
    /// only; ed25519 owners sign digest bytes with [`Self::sign_message`].
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(hash) {
            return Err(KeypairError::DerivationInput);
        }
        match &self.inner {
            SigningKeyInner::P256(sk) => {
                let sig: EcdsaSig = sk
                    .sign_prehash(hash)
                    .map_err(|_| KeypairError::SigningFailed)?;
                let mut out = [0u8; 64];
                out.copy_from_slice(&sig.to_bytes());
                Ok(out)
            }
            SigningKeyInner::Ed25519(_) => Err(KeypairError::NotP256),
        }
    }

    /// The rail seed both role keys expand from: the deterministic RFC 8032
    /// signature over [`derivation::ed25519_derivation_message`] on the
    /// ed25519 rail, or `ECDH(signing_sk, P_derive)` on the P-256 rail.
    pub fn derivation_seed(&self) -> Result<Zeroizing<Vec<u8>>, KeypairError> {
        match &self.inner {
            SigningKeyInner::Ed25519(sk) => {
                let message =
                    derivation::ed25519_derivation_message(sk.verifying_key().as_bytes());
                Ok(Zeroizing::new(sk.sign(&message).to_bytes().to_vec()))
            }
            SigningKeyInner::P256(_) => Ok(Zeroizing::new(
                self.ecdh_raw(&derivation::p_derive())?.to_vec(),
            )),
        }
    }

    /// ECDH with `counterparty`, returning the shared point's x-coordinate.
    /// P-256 rail only; mirrors [`crate::ViewingKey::ecdh`].
    pub fn ecdh(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError> {
        if derivation::is_derivation_point(counterparty) {
            return Err(KeypairError::DerivationInput);
        }
        self.ecdh_raw(counterparty)
    }

    pub(crate) fn ecdh_raw(&self, counterparty: &P256Pubkey) -> Result<[u8; 32], KeypairError> {
        match &self.inner {
            SigningKeyInner::P256(sk) => {
                derivation::ecdh_x(&SecretKey::from(sk.as_nonzero_scalar()), counterparty)
            }
            SigningKeyInner::Ed25519(_) => Err(KeypairError::NotP256),
        }
    }
}

impl From<&solana_keypair::Keypair> for SigningKey {
    fn from(keypair: &solana_keypair::Keypair) -> Self {
        Self::from_ed25519_bytes(keypair.secret_bytes())
    }
}
