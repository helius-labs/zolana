use borsh::BorshDeserialize;
use zolana_event::OutputDataEncoding;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{random_salt, PublicKey, ShieldedAddress, ViewingKey};

use super::{sender_owner_tag, ConfidentialTransaction};
use crate::{
    error::TransactionError,
    instructions::transact::{shape::canonical_shape, ExternalData, SppProofInputs},
    keys::{ShieldedKeys, TransactionKeyRequest},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    EncryptedScheme,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedOwnerTag {
    pub tag: OwnerTag,
    pub resolved: [u8; 32],
}

impl ConfidentialTransaction {
    /// Obtain the sender address and transaction viewing key, then encrypt.
    ///
    /// Steps:
    /// 1. Get the sender address from `shielded_keys`.
    /// 2. Derive the transaction viewing key from the first nullifier.
    /// 3. Delegate to [`Self::encrypt_with_viewing_key`].
    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Get the sender address.
        let sender = shielded_keys.address()?;
        // 2. Derive the transaction viewing key from the first nullifier.
        let tx_viewing_key = shielded_keys.transaction_keys(&[TransactionKeyRequest {
            viewing_pubkey: sender.viewing_pubkey,
            first_nullifier: self.first_nullifier,
        }])?;
        let got = tx_viewing_key.len();
        let tx_viewing_key = tx_viewing_key
            .into_iter()
            .next()
            .ok_or(TransactionError::IncompleteDerivation { got, want: 1 })?;

        // 3. Encrypt using the supplied address and derived viewing key.
        self.encrypt_with_viewing_key(&sender, &tx_viewing_key)
    }

    /// Consume the transaction and encrypt with its supplied transaction viewing key.
    ///
    /// Steps:
    /// 1. If not already finalized, select a shape, convert wallet inputs and pad
    ///    the input and output slots.
    /// 2. Derive and assign output blindings using the final slot order.
    /// 3. Resolve output owner tags and public settlement transfers.
    /// 4. Encrypt each output using a fresh salt from the OS RNG.
    /// 5. Check each encrypted slot's owner tag and assemble its commitment,
    ///    owner tag and ciphertext in output order.
    /// 6. Build the external data and return the assembled proof inputs.
    pub fn encrypt_with_viewing_key(
        mut self,
        sender: &ShieldedAddress,
        tx_viewing_key: &ViewingKey,
    ) -> Result<SppProofInputs, TransactionError> {
        // 1. Select a shape and finalize the input and output slots if needed.
        if self.padded_inputs.is_none() {
            let n_in = self.inputs.len();
            let mut n_out = self.outputs.len();
            for asset in self.assets(&self.outputs)? {
                if self.change(&asset)? > 0 {
                    n_out = n_out
                        .checked_add(1)
                        .ok_or(TransactionError::TooManyOutputs)?;
                }
            }
            let shape = canonical_shape(n_in, n_out)?;
            self.pad_utxos(shape, sender)?;
        }
        // 2. Derive and assign output blindings using the final slot order.
        let output_blinding_seed =
            derive_output_blinding_seed(&self.first_nullifier, &self.blinding_seed)?;
        for (index, output) in self.outputs.iter_mut().enumerate() {
            let index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            output.blinding = derive_transact_output_blinding(
                &self.first_nullifier,
                &output_blinding_seed,
                index,
            )?;
        }
        // 3. Resolve output owner tags and public settlement transfers.
        let owner_tags = self.owner_tags(&sender.signing_pubkey)?;
        let interface_transfers = self.interface_transfers()?;

        // 4. Encrypt each output with a fresh OS RNG salt.
        let salt = random_salt();
        let slots = self
            .outputs
            .iter()
            .enumerate()
            .map(|(slot_index, output)| {
                let address = output
                    .owner_address
                    .ok_or(TransactionError::OutputWithoutOwner { slot_index })?;
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

        // 5. Check owner tags and assemble commitments and ciphertexts in order.
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        for (slot_index, ((output, owner_tag), slot)) in
            self.outputs.iter().zip(owner_tags).zip(slots).enumerate()
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

        // 6. Build external data and return the prepared input and output slots.
        let external_data = ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            salt,
            transact_outputs,
            resolved_owner_tags,
            vec![],
        )
        .with_interface_transfers(interface_transfers)?;

        Ok(SppProofInputs {
            input_utxos: self.padded_inputs.ok_or(TransactionError::NoInputs)?,
            output_utxos: self.outputs,
            blinding_seed: self.blinding_seed,
            output_tree_id: self.output_tree_id,
            external_data,
            payer: self.payer,
        })
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
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        let sender_tag = self.sender_owner_tag(sender)?;
        let mut owner_tags = Vec::with_capacity(self.outputs.len());
        for (slot_index, output) in self.outputs.iter().enumerate() {
            let resolved = output
                .owner_address
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
}
