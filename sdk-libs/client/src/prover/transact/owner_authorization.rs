use spr_keypair::{PublicKey, SigningKey};
use spr_transaction::instructions::transact::transact_message_hash;

use crate::{error::ClientError, prover::transact::EddsaAuthorization};

#[derive(Clone, Copy)]
pub enum OwnerAuthorization<'a> {
    SigningKey(&'a SigningKey),
    /// Signature over [`SppProofInputs::message_hash`](spr_transaction::instructions::transact::SppProofInputs::message_hash), verified before any proof request carries it.
    Prepared {
        owner: PublicKey,
        signature: [u8; 64],
    },
}

impl<'a> From<&'a SigningKey> for OwnerAuthorization<'a> {
    fn from(key: &'a SigningKey) -> Self {
        Self::SigningKey(key)
    }
}

impl OwnerAuthorization<'_> {
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::SigningKey(key) => key.pubkey(),
            Self::Prepared { owner, .. } => *owner,
        }
    }

    pub(crate) fn authorize(
        &self,
        private_tx: &[u8; 32],
        external_data_hash: &[u8; 32],
    ) -> Result<EddsaAuthorization, ClientError> {
        let message_digest = transact_message_hash(private_tx, external_data_hash);
        let owner_public_key = self.public_key().as_ed25519()?;
        let owner_signature = match self {
            Self::SigningKey(key) => key.sign_message(&message_digest)?,
            Self::Prepared { owner, signature } => {
                if !owner.verify_message(&message_digest, signature) {
                    return Err(ClientError::OwnerSignatureMismatch);
                }
                *signature
            }
        };
        Ok(EddsaAuthorization {
            owner_public_key,
            owner_signature,
            message_digest,
        })
    }
}
