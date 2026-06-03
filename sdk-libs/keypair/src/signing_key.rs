use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature as EcdsaSig, SigningKey as EcdsaSigningKey, VerifyingKey};
use p256::SecretKey;
use rand::rngs::OsRng;
use solana_keypair::Keypair;
use solana_signature::Signature as SolSignature;
use solana_signer::Signer as SolSigner;
use zeroize::Zeroizing;

use crate::error::KeypairError;
use crate::pubkey::{P256Pubkey, PublicKey};

pub enum SigningKey {
    P256(SecretKey),
    Ed25519(Keypair),
}

impl SigningKey {
    pub fn new_p256() -> Self {
        Self::P256(SecretKey::random(&mut OsRng))
    }

    pub fn new_ed25519() -> Self {
        Self::Ed25519(Keypair::new())
    }

    pub fn from_p256_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let secret_key =
            SecretKey::from_slice(bytes).map_err(|_| KeypairError::InvalidSecretKey)?;
        Ok(Self::P256(secret_key))
    }

    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        Self::Ed25519(Keypair::new_from_array(*seed))
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = [0u8; 32];
        match self {
            Self::P256(secret_key) => out.copy_from_slice(secret_key.to_bytes().as_slice()),
            Self::Ed25519(kp) => out.copy_from_slice(kp.secret_bytes()),
        }
        Zeroizing::new(out)
    }

    pub fn pubkey(&self) -> PublicKey {
        match self {
            Self::P256(secret_key) => {
                PublicKey::from_p256(&P256Pubkey::from_p256(&secret_key.public_key()))
            }
            Self::Ed25519(kp) => {
                let kb = kp.to_bytes();
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&kb[32..64]);
                PublicKey::from_ed25519(&pubkey)
            }
        }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        match self {
            Self::P256(secret_key) => {
                let signing = EcdsaSigningKey::from_bytes(&secret_key.to_bytes())
                    .expect("valid scalar from a valid secret key");
                let sig: EcdsaSig = signing.sign(msg);
                out.copy_from_slice(sig.to_bytes().as_slice());
            }
            Self::Ed25519(kp) => {
                let sig = kp.sign_message(msg);
                out.copy_from_slice(sig.as_ref());
            }
        }
        out
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        match self {
            Self::P256(secret_key) => {
                let vk = VerifyingKey::from(secret_key.public_key());
                match EcdsaSig::from_slice(sig) {
                    Ok(parsed) => vk.verify(msg, &parsed).is_ok(),
                    Err(_) => false,
                }
            }
            Self::Ed25519(_) => match self.pubkey().as_ed25519() {
                Ok(pubkey) => SolSignature::from(*sig).verify(&pubkey, msg),
                Err(_) => false,
            },
        }
    }
}
