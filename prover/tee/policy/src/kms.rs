//! Ed25519 signers: an AWS KMS key, which signs without this process ever
//! holding it, and a local key for tests.

use std::future::Future;

use anyhow::{bail, Context, Result};
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
    Client,
};

/// DER prefix of an Ed25519 SubjectPublicKeyInfo, before the 32 key bytes.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Signs a message with one Ed25519 key.
pub trait Ed25519Signer {
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> impl Future<Output = Result<[u8; 64]>> + Send;
}

/// A KMS key of spec `ECC_NIST_EDWARDS25519`.
pub struct KmsSigner {
    client: Client,
    key_id: String,
    public_key: [u8; 32],
}

impl KmsSigner {
    /// `key_id` is a key id, ARN or `alias/...`.
    pub async fn new(client: Client, key_id: impl Into<String>) -> Result<Self> {
        let key_id = key_id.into();
        let public_key = kms_public_key(&client, &key_id).await?;
        Ok(Self {
            client,
            key_id,
            public_key,
        })
    }
}

/// The raw Ed25519 public key of a KMS key.
pub async fn kms_public_key(client: &Client, key_id: &str) -> Result<[u8; 32]> {
    let output = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .with_context(|| format!("read the public key of {key_id}"))?;
    let der = output
        .public_key()
        .context("KMS returned no public key")?
        .as_ref();
    match der.strip_prefix(&ED25519_SPKI_PREFIX) {
        Some(key) if key.len() == 32 => Ok(key.try_into().expect("32 bytes")),
        _ => bail!("{key_id} is not an Ed25519 key"),
    }
}

impl Ed25519Signer for KmsSigner {
    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    async fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(message))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
            .send()
            .await
            .with_context(|| format!("sign with {}", self.key_id))?;
        let signature = output
            .signature()
            .context("KMS returned no signature")?
            .as_ref();
        signature.try_into().with_context(|| {
            format!(
                "{} returned a {}-byte signature",
                self.key_id,
                signature.len()
            )
        })
    }
}

/// A key held in memory, for tests.
#[cfg(test)]
pub struct LocalSigner(pub ed25519_dalek::SigningKey);

#[cfg(test)]
impl LocalSigner {
    pub fn seed(seed: u8) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }
}

#[cfg(test)]
impl Ed25519Signer for LocalSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    async fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer;
        Ok(self.0.sign(message).to_bytes())
    }
}
