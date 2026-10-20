use std::collections::HashSet;

use zolana_event::MessageData;
use zolana_interface::instruction::instruction_data::transact::OwnerTag;
use zolana_keypair::{viewing_key::ViewTag, ShieldedAddress, X25519Pubkey};
use zolana_transaction::{
    instructions::transact::{ConfidentialTransaction, OutputEncoder, ResolvedOwnerTag},
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    DecodeCx, EncryptedScheme, OwnerCx, TransactionError, Utxo, UtxoSerialization,
};

/// Publishes no recipient viewing key.
pub struct RingAnonymous;

impl UtxoSerialization for RingAnonymous {
    const SCHEME: EncryptedScheme = EncryptedScheme::RingAnonymous;
    type Plaintext = ConfidentialOutputPlaintext;
    type EncodeCx = ConfidentialEncode;

    fn decrypt(body: &[u8], cx: &DecodeCx) -> Result<Vec<u8>, TransactionError> {
        let tx_viewing_pk = cx
            .tx_viewing_pk
            .ok_or(TransactionError::MissingEncryptionContext)?;
        let salt = cx.salt.ok_or(TransactionError::MissingEncryptionContext)?;
        Ok(cx
            .viewing_key
            .decrypt_utxo(body, &tx_viewing_pk, salt, cx.slot_index)?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self::Plaintext, TransactionError> {
        ConfidentialOutputPlaintext::deserialize(bytes)
    }

    fn into_utxos(plaintext: Self::Plaintext, cx: &OwnerCx) -> Result<Vec<Utxo>, TransactionError> {
        Confidential::into_utxos(plaintext, cx)
    }

    fn from_utxos(
        utxos: &[Utxo],
        owner: &OwnerCx,
        cx: &Self::EncodeCx,
    ) -> Result<Self::Plaintext, TransactionError> {
        Confidential::from_utxos(utxos, owner, cx)
    }

    fn serialize(plaintext: &Self::Plaintext) -> Result<Vec<u8>, TransactionError> {
        plaintext.serialize()
    }

    fn encrypt(bytes: &[u8], cx: &Self::EncodeCx) -> Result<Vec<u8>, TransactionError> {
        Ok(cx
            .tx
            .encrypt_slot(&cx.recipient_pubkey, bytes, cx.salt, cx.slot_index)?)
    }
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousViewTags {
    sender: ViewTag,
    bootstrap: HashSet<X25519Pubkey>,
}

impl AnonymousViewTags {
    /// `sender` is the wallet's next unused `sender_view_tag`.
    pub fn new(sender: ViewTag) -> Self {
        Self {
            sender,
            bootstrap: HashSet::new(),
        }
    }

    /// Anyone who knows `recipient` links its outputs through the bootstrap tag.
    pub fn with_bootstrap_tag(mut self, recipient: X25519Pubkey) -> Self {
        self.bootstrap.insert(recipient);
        self
    }
}

impl OutputEncoder for AnonymousViewTags {
    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        transaction
            .outputs()
            .iter()
            .enumerate()
            .map(|(slot_index, output)| {
                let resolved = match output.owner_address {
                    _ if output.is_compact() => [0; 32],
                    Some(owner) if owner.signing_pubkey != sender.signing_pubkey => {
                        if !self.bootstrap.contains(&owner.viewing_pubkey) {
                            return Err(TransactionError::RecipientViewTagUnset { slot_index });
                        }
                        owner.viewing_pubkey.u()
                    }
                    _ => self.sender,
                };
                Ok(ResolvedOwnerTag {
                    tag: OwnerTag::Inline(resolved),
                    resolved,
                })
            })
            .collect()
    }

    fn encode_slot(
        &self,
        plaintext: &ConfidentialOutputPlaintext,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, TransactionError> {
        RingAnonymous::encode_plaintext(plaintext, view_tag, cx)
    }
}
