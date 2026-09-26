use borsh::BorshDeserialize;
use zolana_event::OutputDataEncoding;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{random_salt, PublicKey, ShieldedAddress, ShieldedKeypair, ViewingKey};

use super::{sender_owner_tag, ConfidentialTransaction, FinalizedTransaction};
use crate::{
    error::TransactionError,
    instructions::transact::{ExternalData, SppProofInputs},
    keys::{ShieldedKeys, TransactionKeyRequest},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    EncryptedScheme,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedOwnerTag {
    pub tag: OwnerTag,
    pub resolved: [u8; 32],
}

impl ConfidentialTransaction {
    /// Finalize the transaction, then encrypt it with keys from `shielded_keys`.
    ///
    /// Steps:
    /// 1. Get the sender address from `shielded_keys`.
    /// 2. Delegate to [`Self::finalize`] and [`FinalizedTransaction::encrypt`].
    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Get the sender address.
        let sender = shielded_keys.address()?;
        // 2. Finalize and encrypt.
        self.finalize(&sender)?
            .encrypt_with_sender_keys(shielded_keys)
    }

    /// Finalize the transaction, then encrypt it with the supplied transaction
    /// viewing key. See [`Self::finalize`] and
    /// [`FinalizedTransaction::encrypt_with_viewing_key`].
    pub fn encrypt_with_viewing_key(
        self,
        sender: &ShieldedAddress,
        tx_viewing_key: &ViewingKey,
    ) -> Result<SppProofInputs, TransactionError> {
        self.finalize(sender)?
            .encrypt_with_viewing_key(tx_viewing_key)
    }

    pub fn sender_owner_tag(
        &self,
        sender: &PublicKey,
    ) -> Result<ResolvedOwnerTag, TransactionError> {
        let (tag, resolved) =
            sender_owner_tag(sender, &self.payer, self.ring_program_id.is_some())?;
        Ok(ResolvedOwnerTag { tag, resolved })
    }

    pub fn owner_tags(
        &self,
        sender: &PublicKey,
        padding_owner: Option<&ShieldedAddress>,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        let sender_tag = self.sender_owner_tag(sender)?;
        let mut owner_tags = Vec::with_capacity(self.outputs.len());
        for (slot_index, output) in self.outputs.iter().enumerate() {
            let resolved = output
                .owner_address
                .as_ref()
                .or(padding_owner)
                .ok_or(TransactionError::OutputWithoutOwner { slot_index })?
                .signing_pubkey
                .confidential_view_tag()?;
            owner_tags.push(if resolved == sender_tag.resolved {
                sender_tag
            } else {
                ResolvedOwnerTag {
                    tag: OwnerTag::Inline(resolved),
                    resolved,
                }
            });
        }
        Ok(owner_tags)
    }

    /// Dummy outputs have no owner, so their ciphertexts and owner tags borrow
    /// one: the sender when it receives an output, else the first output's
    /// owner. A transaction without owned outputs encrypts them to a throwaway
    /// keypair nobody holds.
    pub(super) fn padding_owner(
        &self,
        sender: &ShieldedAddress,
    ) -> Result<ShieldedAddress, TransactionError> {
        let owners = || {
            self.outputs
                .iter()
                .filter_map(|output| output.owner_address)
        };
        match owners()
            .find(|owner| owner == sender)
            .or_else(|| owners().next())
        {
            Some(owner) => Ok(owner),
            None => Ok(ShieldedKeypair::new_ed25519()?.shielded_address()?),
        }
    }
}

impl FinalizedTransaction {
    /// Derive the transaction viewing key from `shielded_keys`, then encrypt.
    ///
    /// Steps:
    /// 1. Require `shielded_keys` to hold the sender this transaction was
    ///    finalized for.
    /// 2. Derive the transaction viewing key from the first nullifier.
    /// 3. Delegate to [`Self::encrypt_with_viewing_key`].
    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Require the finalized sender.
        if shielded_keys.address()? != self.sender {
            return Err(TransactionError::SenderAddressMismatch);
        }
        // 2.-3. Derive the transaction viewing key and encrypt.
        self.encrypt_with_sender_keys(shielded_keys)
    }

    fn encrypt_with_sender_keys<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        let tx_viewing_key = shielded_keys.transaction_keys(&[TransactionKeyRequest {
            viewing_pubkey: self.sender.viewing_pubkey,
            first_nullifier: self.first_nullifier()?,
        }])?;
        let got = tx_viewing_key.len();
        let tx_viewing_key = tx_viewing_key
            .into_iter()
            .next()
            .ok_or(TransactionError::IncompleteDerivation { got, want: 1 })?;
        self.encrypt_with_viewing_key(&tx_viewing_key)
    }

    /// Consume the transaction and encrypt with its supplied transaction viewing key.
    ///
    /// Steps:
    /// 1. Require one owner tag per output slot.
    /// 2. Encrypt each output using a fresh salt from the OS RNG.
    /// 3. Check each encrypted slot's owner tag and assemble its commitment,
    ///    owner tag and ciphertext in output order.
    /// 4. Build the external data and return the assembled proof inputs.
    pub fn encrypt_with_viewing_key(
        self,
        tx_viewing_key: &ViewingKey,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Require one owner tag per output slot.
        if self.owner_tags.len() != self.output_utxos.len() {
            return Err(TransactionError::OwnerTagCountMismatch {
                got: self.owner_tags.len(),
                expected: self.output_utxos.len(),
            });
        }

        // 2. Encrypt each output with a fresh OS RNG salt.
        let salt = random_salt();
        let slots = self
            .output_utxos
            .iter()
            .enumerate()
            .map(|(slot_index, output)| {
                let address = output.owner_address.unwrap_or(self.padding_owner);
                let mut message = Confidential::encode_plaintext(
                    &ConfidentialOutputPlaintext {
                        asset_id: output.asset.asset_id,
                        amount: output.amount,
                        blinding: output.blinding,
                        ring_program_id: output.ring_program_id,
                        data: output.data.clone(),
                    },
                    address.signing_pubkey.confidential_view_tag()?,
                    &ConfidentialEncode {
                        tx: tx_viewing_key.clone(),
                        recipient_pubkey: address.viewing_pubkey,
                        salt,
                        slot_index: slot_index as u32,
                    },
                )?;
                if output.ring_program_id.is_some() {
                    let OutputDataEncoding::Encrypted(mut blob) =
                        OutputDataEncoding::try_from_slice(&message.data)
                            .map_err(|error| TransactionError::Deserialize(error.to_string()))?
                    else {
                        return Err(TransactionError::BadDiscriminator(
                            EncryptedScheme::Confidential.as_byte(),
                        ));
                    };
                    *blob.first_mut().ok_or(TransactionError::MissingOutput)? =
                        EncryptedScheme::RingConfidential.as_byte();
                    message.data = borsh::to_vec(&OutputDataEncoding::Encrypted(blob))
                        .map_err(|error| TransactionError::Deserialize(error.to_string()))?;
                }
                Ok(message)
            })
            .collect::<Result<Vec<_>, TransactionError>>()?;

        // 3. Check owner tags and assemble commitments and ciphertexts in order.
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        for (slot_index, ((output, owner_tag), slot)) in self
            .output_utxos
            .iter()
            .zip(&self.owner_tags)
            .zip(slots)
            .enumerate()
        {
            if slot.view_tag != owner_tag.resolved {
                return Err(TransactionError::OwnerTagMismatch { slot_index });
            }
            transact_outputs.push(TransactOutput {
                utxo_hash: output.hash(self.output_tree_id)?,
                owner_tag: owner_tag.tag,
                data: Some(slot.data),
            });
            resolved_owner_tags.push(owner_tag.resolved);
        }

        // 4. Build external data and return the prepared input and output slots.
        let mut external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
        )
        .with_interface_transfers(self.interface_transfers)?;
        external_data.expiry_unix_ts = self.expiry_unix_ts;

        Ok(SppProofInputs {
            input_utxos: self.input_utxos,
            output_utxos: self.output_utxos,
            blinding_seed: self.blinding_seed,
            output_tree_id: self.output_tree_id,
            external_data,
            payer: self.payer,
            cache_accounts: Default::default(),
            program_signers: Vec::new(),
        })
    }
}
