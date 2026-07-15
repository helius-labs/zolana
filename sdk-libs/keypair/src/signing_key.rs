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
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::{
    error::KeypairError,
    pubkey::{P256Pubkey, PublicKey},
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
    pub fn new() -> Self {
        Self {
            inner: SigningKeyInner::P256(SecretKey::random(&mut OsRng)),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| KeypairError::InvalidSecretKey)?;
        Ok(Self {
            inner: SigningKeyInner::P256(secret),
        })
    }

    pub fn from_ed25519(bytes: &[u8; 32]) -> Self {
        Self {
            inner: SigningKeyInner::Ed25519(DalekSigningKey::from_bytes(bytes)),
        }
    }

    pub fn is_ed25519(&self) -> bool {
        matches!(self.inner, SigningKeyInner::Ed25519(_))
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

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        match &self.inner {
            SigningKeyInner::P256(sk) => {
                let signing = EcdsaSigningKey::from(sk);
                let sig: EcdsaSig = signing
                    .sign_prehash(msg)
                    .expect("p256 prehash signing is infallible for a 32-byte digest");
                let mut out = [0u8; 64];
                out.copy_from_slice(&sig.to_bytes());
                out
            }
            SigningKeyInner::Ed25519(sk) => sk.sign(msg).to_bytes(),
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

impl Default for SigningKey {
    fn default() -> Self {
        Self::new()
    }
}
