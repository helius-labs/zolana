use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as DalekSigningKey};
use p256::{
    ecdsa::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        Signature as EcdsaSig, SigningKey as EcdsaSigningKey, VerifyingKey,
    },
    SecretKey,
};
use rand::{rngs::OsRng, RngCore};
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

    /// A fresh random ed25519 key. Mirrors [`Self::new`] (P256) for callers that
    /// need a throwaway key on the ed25519 rail; the secret bytes are zeroized
    /// once copied into the dalek key.
    pub fn new_ed25519() -> Self {
        let mut secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(secret.as_mut());
        Self {
            inner: SigningKeyInner::Ed25519(DalekSigningKey::from_bytes(&secret)),
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
                    // The Solana runtime verifies with `verify_strict`, so this
                    // helper answers the question a caller is really asking:
                    // would the runtime accept this signature.
                    Ok(parsed) => vk.verify_strict(msg, &parsed).is_ok(),
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

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier as Ed25519Verifier;

    use super::*;
    use crate::pubkey::SignatureType;

    /// The committed vector in `sdk-libs/ts/fixtures/keypair/signing_key.json`,
    /// over the empty message.
    const ED25519_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const ED25519_SIGNATURE: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    /// `R` is the identity point and `s` is `k * x mod L`, so `[s]B - [k]A`
    /// recompresses to `R` and the plain verification equation holds.
    const SMALL_ORDER_R_SIGNATURE: &str = concat!(
        "0100000000000000000000000000000000000000000000000000000000000000",
        "756cf9b1d6f0d7a979b9d2af3dc2bc1294ec7cb6daa20eaff534c024fc57920f",
    );

    /// `R` encodes `y = p + 3`, which decodes to a point of full order rather
    /// than being refused outright.
    const NON_CANONICAL_R_SIGNATURE: &str = concat!(
        "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    fn ed25519_fixture_key() -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        hex::decode_to_slice(ED25519_SECRET, &mut secret).unwrap();
        (SigningKey::from_ed25519(&secret), secret)
    }

    fn signature_bytes(value: &str) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        hex::decode_to_slice(value, &mut bytes).unwrap();
        bytes
    }

    /// `SigningKey::verify` mirrors the Solana runtime, so the small-order `R`
    /// below is refused even though the plain verification equation accepts it.
    /// `sdk-libs/ts/keypair/test/ed25519-acceptance.test.ts` asserts the same
    /// three vectors and the same outcomes.
    #[test]
    fn ed25519_verify_mirrors_the_runtime() {
        let (key, secret) = ed25519_fixture_key();
        let verifying = DalekSigningKey::from_bytes(&secret).verifying_key();

        assert!(key.verify(&[], &signature_bytes(ED25519_SIGNATURE)));

        let small_order_r = signature_bytes(SMALL_ORDER_R_SIGNATURE);
        let parsed = ed25519_dalek::Signature::from_bytes(&small_order_r);
        assert!(verifying.verify(&[], &parsed).is_ok());
        assert!(verifying.verify_strict(&[], &parsed).is_err());
        assert!(!key.verify(&[], &small_order_r));

        assert!(!key.verify(&[], &signature_bytes(NON_CANONICAL_R_SIGNATURE)));
    }

    /// `new_ed25519` produces a genuine ed25519 key: it reports the ed25519 rail,
    /// signs and verifies a message (which an off-curve key could not), and its
    /// confidential view tag is the raw 32-byte ed25519 public key. `new` stays on
    /// the P256 rail.
    #[test]
    fn new_ed25519_is_a_working_ed25519_key() {
        let key = SigningKey::new_ed25519();
        assert!(key.is_ed25519());
        assert!(!SigningKey::new().is_ed25519());

        let msg = [7u8; 32];
        let sig = key.sign(&msg);
        assert!(key.verify(&msg, &sig));

        let pubkey = key.pubkey();
        assert_eq!(pubkey.signature_type().unwrap(), SignatureType::Ed25519);
        assert_eq!(
            pubkey.confidential_view_tag().unwrap(),
            pubkey.as_ed25519().unwrap()
        );
    }
}
