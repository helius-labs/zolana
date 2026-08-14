use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as DalekSigningKey, Verifier as Ed25519Verifier,
};
use p256::{
    ecdsa::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        Signature as EcdsaSig, SigningKey as EcdsaSigningKey, VerifyingKey,
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

enum SigningKeyInner {
    P256(SecretKey),
    Ed25519(DalekSigningKey),
}

pub struct SigningKey {
    inner: SigningKeyInner,
}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        match &self.inner {
            SigningKeyInner::P256(sk) => Self {
                inner: SigningKeyInner::P256(sk.clone()),
            },
            SigningKeyInner::Ed25519(sk) => Self {
                inner: SigningKeyInner::Ed25519(DalekSigningKey::from_bytes(sk.as_bytes())),
            },
        }
    }
}

impl SigningKey {
    pub fn new_p256() -> Self {
        Self {
            inner: SigningKeyInner::P256(SecretKey::random(&mut OsRng)),
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
        let secret = SecretKey::from_slice(bytes).map_err(|_| KeypairError::InvalidSecretKey)?;
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
                PublicKey::from_p256(&P256Pubkey::from_p256(&sk.public_key()))
            }
            SigningKeyInner::Ed25519(sk) => {
                let vk = sk.verifying_key();
                PublicKey::from_ed25519(vk.as_bytes())
            }
        }
    }

    /// The derivation-input guard is meaningful on the ed25519 arm, where
    /// `msg` is the message itself and signing it would yield the derivation
    /// seed. The P256 arm takes a prehash, so the check can only fire on a
    /// digest that happens to start with the prefix; that rail's seed is
    /// `ECDH(sk, P_derive)`, guarded by the committed-point check in
    /// [`Self::ecdh`].
    // TODO: rename to be consistent with ShieldedKeypair
    pub fn sign(&self, msg: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(msg) {
            return Err(KeypairError::DerivationInput);
        }
        self.sign_raw(msg)
    }

    pub(crate) fn sign_raw(&self, msg: &[u8]) -> Result<[u8; 64], KeypairError> {
        match &self.inner {
            SigningKeyInner::P256(sk) => {
                // TODO: check whether this transformation is necessary or can be streamlined
                let signing = EcdsaSigningKey::from(sk);
                let sig: EcdsaSig = signing
                    .sign_prehash(msg)
                    .map_err(|_| KeypairError::SigningFailed)?;
                let mut out = [0u8; 64];
                out.copy_from_slice(&sig.to_bytes());
                Ok(out)
            }
            SigningKeyInner::Ed25519(sk) => Ok(sk.sign(msg).to_bytes()),
        }
    }

    /// Sign an arbitrary message exactly as Solana's secp256r1 precompile
    /// verifies it: ECDSA over SHA-256(message), normalized to low-S.
    pub fn sign_p256_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput);
        }
        let SigningKeyInner::P256(sk) = &self.inner else {
            return Err(KeypairError::NotP256);
        };
        let signing = EcdsaSigningKey::from(sk);
        let digest = Sha256::digest(message);
        let signature: EcdsaSig = signing
            .sign_prehash(&digest)
            .map_err(|_| KeypairError::InvalidSecretKey)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut out = [0u8; 64];
        out.copy_from_slice(&signature.to_bytes());
        Ok(out)
    }

    /// The rail seed both role keys expand from: the deterministic RFC 8032
    /// signature over [`derivation::ed25519_derivation_message`] on the
    /// ed25519 rail, or `ECDH(signing_sk, P_derive)` on the P-256 rail.
    pub fn derivation_seed(&self) -> Result<Zeroizing<Vec<u8>>, KeypairError> {
        match self.curve() {
            Curve::Ed25519 => {
                let message = derivation::ed25519_derivation_message(&self.pubkey().as_ed25519()?);
                Ok(Zeroizing::new(self.sign_raw(&message)?.to_vec()))
            }
            Curve::P256 => Ok(Zeroizing::new(
                self.ecdh_raw(&derivation::p_derive())?.to_vec(),
            )),
            Curve::Pda => Err(KeypairError::PdaCannotSign),
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
            SigningKeyInner::P256(sk) => derivation::ecdh_x(sk, counterparty),
            SigningKeyInner::Ed25519(_) => Err(KeypairError::NotP256),
        }
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        match &self.inner {
            SigningKeyInner::P256(sk) => {
                let vk = VerifyingKey::from(sk.public_key());
                match EcdsaSig::from_slice(sig) {
                    Ok(parsed) => vk.verify_prehash(msg, &parsed).is_ok(),
                    Err(_) => false,
                }
            }
            SigningKeyInner::Ed25519(sk) => {
                let vk = sk.verifying_key();
                match ed25519_dalek::Signature::try_from(sig.as_slice()) {
                    Ok(parsed) => vk.verify(msg, &parsed).is_ok(),
                    Err(_) => false,
                }
            }
        }
    }
}

impl From<&solana_keypair::Keypair> for SigningKey {
    fn from(keypair: &solana_keypair::Keypair) -> Self {
        Self::from_ed25519_bytes(keypair.secret_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `new_ed25519` produces a genuine ed25519 key: it reports the ed25519 rail,
    /// signs and verifies a message (which an off-curve key could not), and its
    /// confidential view tag is the raw 32-byte ed25519 public key. `new_p256`
    /// stays on the P256 rail.
    #[test]
    fn new_ed25519_is_a_working_ed25519_key() {
        let key = SigningKey::new_ed25519();
        assert_eq!(key.curve(), Curve::Ed25519);
        assert_eq!(SigningKey::new_p256().curve(), Curve::P256);

        let msg = [7u8; 32];
        let sig = key.sign(&msg).expect("ed25519 signing");
        assert!(key.verify(&msg, &sig));

        let pubkey = key.pubkey();
        assert_eq!(pubkey.curve().unwrap(), Curve::Ed25519);
        assert_eq!(
            pubkey.confidential_view_tag().unwrap(),
            pubkey.as_ed25519().unwrap()
        );
    }

    #[test]
    fn p256_message_signature_is_sha256_and_low_s() {
        let key = SigningKey::new_p256();
        let message = b"registry binding";
        let raw = key.sign_p256_message(message).expect("P256 signature");
        let signature = EcdsaSig::from_slice(&raw).expect("compact signature");
        assert!(signature.normalize_s().is_none(), "signature must be low-S");

        let SigningKeyInner::P256(secret) = &key.inner else {
            unreachable!();
        };
        let verifying = VerifyingKey::from(secret.public_key());
        let digest = Sha256::digest(message);
        assert!(verifying.verify_prehash(&digest, &signature).is_ok());
    }

    #[test]
    fn ed25519_key_cannot_make_p256_precompile_signature() {
        let key = SigningKey::new_ed25519();
        assert_eq!(
            key.sign_p256_message(b"registry binding"),
            Err(KeypairError::NotP256)
        );
    }
}
