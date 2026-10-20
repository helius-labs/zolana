use solana_address::Address;
use zolana_event::MessageData;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::SALT_LEN, random_salt, PublicKey, ShieldedAddress, ViewingKey, X25519Pubkey,
};

use super::{sender_owner_tag, ConfidentialTransaction, FinalizedTransaction};
use crate::{
    error::TransactionError,
    instructions::transact::{ExternalData, SppProofInputs, SppProofOutputUtxo},
    keys::{first_input_transaction_key, ShieldedKeys},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    Data, SOL_ASSET_ID,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedOwnerTag {
    pub tag: OwnerTag,
    pub resolved: [u8; 32],
}

/// One real output slot in its final position, about to be sealed.
pub struct SlotEncode<'a> {
    pub output: &'a SppProofOutputUtxo,
    pub owner_tag: ResolvedOwnerTag,
    pub sender: &'a ShieldedAddress,
    pub first_nullifier: [u8; 32],
    pub ring_program_id: Option<Address>,
    pub tx_viewing_key: &'a ViewingKey,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

/// The output rail of a transaction, [`Confidential`] is the default ring's.
pub trait OutputEncoder {
    /// `None` keeps the seed the transaction was built with.
    fn output_blinding_seed(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Option<[u8; 32]>, TransactionError> {
        let _ = (transaction, sender);
        Ok(None)
    }

    /// One tag per output slot, in slot order.
    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError>;

    /// `output_hashes` are the commitments of every real slot in order.
    fn salt(
        &self,
        tx_viewing_pk: &X25519Pubkey,
        output_hashes: &[[u8; 32]],
    ) -> Result<[u8; SALT_LEN], TransactionError> {
        let _ = (tx_viewing_pk, output_hashes);
        Ok(random_salt())
    }

    /// The published message of one real slot, its `view_tag` must equal the resolved owner tag.
    fn encode_slot(&self, slot: &SlotEncode<'_>) -> Result<MessageData, TransactionError>;
}

impl OutputEncoder for Confidential {
    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        transaction.owner_tags(&sender.signing_pubkey)
    }

    fn encode_slot(&self, slot: &SlotEncode<'_>) -> Result<MessageData, TransactionError> {
        if slot.output.owner_address.is_some() {
            return slot
                .output
                .seal(slot.slot_index, slot.tx_viewing_key, slot.salt);
        }
        // A dummy publishes random bytes of a real slot's length under its owner tag.
        let len = dummy_ciphertext_len(slot.ring_program_id, slot.salt)?;
        Ok(MessageData {
            view_tag: slot.owner_tag.resolved,
            data: std::iter::repeat_with(random_salt)
                .flatten()
                .take(len)
                .collect(),
        })
    }
}

pub struct OutputEncryption<'a, E> {
    pub sender: &'a ShieldedAddress,
    pub tx_viewing_key: &'a ViewingKey,
    pub encoder: &'a E,
}

impl<E: OutputEncoder> OutputEncryption<'_, E> {
    pub fn encrypt(
        self,
        transaction: ConfidentialTransaction,
    ) -> Result<SppProofInputs, TransactionError> {
        transaction
            .finalize_with(self.sender, self.encoder)?
            .encrypt_with(self.tx_viewing_key, self.encoder)
    }
}

impl ConfidentialTransaction {
    /// Finalize the transaction, then encrypt it with keys from `shielded_keys`.
    ///
    /// Steps:
    /// 1. Get the sender address from `shielded_keys`.
    /// 2. Delegate to [`Self::finalize`] and [`FinalizedTransaction::encrypt_with_keys`].
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
        let (tag, resolved) = sender_owner_tag(sender, &self.payer)?;
        Ok(ResolvedOwnerTag { tag, resolved })
    }

    pub fn owner_tags(
        &self,
        sender: &PublicKey,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        let sender_tag = self.sender_owner_tag(sender)?;
        let mut owner_tags = Vec::with_capacity(self.outputs.len());
        for (slot_index, output) in self.outputs.iter().enumerate() {
            if output.is_compact() {
                owner_tags.push(ResolvedOwnerTag {
                    tag: OwnerTag::Inline([0u8; 32]),
                    resolved: [0u8; 32],
                });
                continue;
            }
            let resolved = match output.owner_address {
                Some(address) => address.signing_pubkey.confidential_view_tag()?,
                None => output
                    .owner_tag
                    .ok_or(TransactionError::DummyOutputWithoutOwnerTag { slot_index })?,
            };
            // Padding that borrows the sender's tag takes the sender's encoding.
            // A different encoding would mark the slot as padding.
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
}

impl FinalizedTransaction {
    /// Derive the transaction viewing key from `shielded_keys`, then encrypt.
    ///
    /// Steps:
    /// 1. Require `shielded_keys` to hold the sender this transaction was
    ///    finalized for.
    /// 2. Derive the transaction viewing key from the first nullifier.
    /// 3. Delegate to [`Self::encrypt_with_viewing_key`].
    pub fn encrypt_with_keys<K: ShieldedKeys + ?Sized>(
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

    pub fn encrypt(self) -> Result<SppProofInputs, TransactionError> {
        let secret = self
            .tx_viewing_key
            .ok_or(TransactionError::MissingSyncedTransactionKey)?;
        let key = ViewingKey::from_canonical_bytes(&secret)?;
        self.encrypt_with_viewing_key(&key)
    }

    fn encrypt_with_sender_keys<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        let tx_viewing_key = first_input_transaction_key(
            shielded_keys,
            self.sender.viewing_pubkey,
            self.first_nullifier()?,
            self.tx_viewing_key,
        )?;
        self.encrypt_with_viewing_key(&tx_viewing_key)
    }

    /// Consume the transaction and encrypt with its supplied transaction viewing key.
    ///
    /// Steps:
    /// 1. Require one owner tag per output slot.
    /// 2. Hash every real output and draw the transaction salt.
    /// 3. Seal each real slot in output order and check its published owner
    ///    tag. Compact padding is left out.
    /// 4. Build the external data and return the assembled proof inputs.
    pub fn encrypt_with_viewing_key(
        self,
        tx_viewing_key: &ViewingKey,
    ) -> Result<SppProofInputs, TransactionError> {
        self.encrypt_with(tx_viewing_key, &Confidential)
    }

    fn encrypt_with<E: OutputEncoder>(
        self,
        tx_viewing_key: &ViewingKey,
        encoder: &E,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Require one owner tag per output slot.
        if self.owner_tags.len() != self.output_utxos.len() {
            return Err(TransactionError::OwnerTagCountMismatch {
                got: self.owner_tags.len(),
                expected: self.output_utxos.len(),
            });
        }

        // 2. Hash every real output and draw the salt. Compact padding is the
        // trailing suffix SPP fills back in.
        let output_hashes = self
            .output_utxos
            .iter()
            .map(|output| match output.is_compact() {
                true => Ok(None),
                false => output.hash(self.output_tree_id).map(Some),
            })
            .collect::<Result<Vec<_>, TransactionError>>()?;
        let real_hashes: Vec<[u8; 32]> = output_hashes.iter().flatten().copied().collect();
        let salt = encoder.salt(&tx_viewing_key.pubkey(), &real_hashes)?;
        let first_nullifier = self.first_nullifier()?;

        // 3. Seal each real slot and check its owner tag.
        let mut transact_outputs = Vec::with_capacity(real_hashes.len());
        let mut resolved_owner_tags = Vec::with_capacity(real_hashes.len());
        for (slot_index, ((output, owner_tag), utxo_hash)) in self
            .output_utxos
            .iter()
            .zip(&self.owner_tags)
            .zip(output_hashes)
            .enumerate()
        {
            let Some(utxo_hash) = utxo_hash else {
                continue;
            };
            let message = encoder.encode_slot(&SlotEncode {
                output,
                owner_tag: *owner_tag,
                sender: &self.sender,
                first_nullifier,
                ring_program_id: self.ring_program_id,
                tx_viewing_key,
                salt,
                slot_index: slot_index as u32,
            })?;
            if message.view_tag != owner_tag.resolved {
                return Err(TransactionError::OwnerTagMismatch { slot_index });
            }
            transact_outputs.push(TransactOutput {
                utxo_hash,
                owner_tag: owner_tag.tag,
                data: Some(message.data),
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
        })
    }
}

/// A zero output sealed to a throwaway key, the published length of a dummy slot.
fn dummy_ciphertext_len(
    ring_program_id: Option<Address>,
    salt: [u8; SALT_LEN],
) -> Result<usize, TransactionError> {
    let throwaway = ViewingKey::new();
    Ok(Confidential::encode_plaintext(
        &ConfidentialOutputPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 0,
            blinding: [0u8; 32],
            ring_program_id,
            data: Data::default(),
        },
        [0u8; 32],
        &ConfidentialEncode {
            recipient_pubkey: throwaway.pubkey(),
            tx: throwaway,
            salt,
            slot_index: 0,
        },
    )?
    .data
    .len())
}
