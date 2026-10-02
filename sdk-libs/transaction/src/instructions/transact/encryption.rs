use borsh::BorshDeserialize;
use zolana_event::{MessageData, OutputDataEncoding};
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{
    constants::{P256_PUBKEY_LEN, SALT_LEN},
    random_salt, PublicKey, ShieldedAddress, ViewingKey,
};

use super::{sender_owner_tag, ConfidentialTransaction, SppProofOutputUtxo};
use crate::{
    error::TransactionError,
    instructions::transact::{shape::canonical_shape, ExternalData, SppProofInputs},
    keys::{ShieldedKeys, TransactionKeyRequest},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding},
    Data, EncryptedScheme, SOL_ASSET_ID,
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
    /// 4. Encrypt each real output using a fresh salt from the OS RNG.
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

        // 4. Encrypt each real output with a fresh OS RNG salt.
        let salt = random_salt();
        let slots = (0u32..)
            .zip(&self.outputs)
            .map(|(slot_index, output)| seal_output(output, slot_index, tx_viewing_key, salt))
            .collect::<Result<Vec<_>, TransactionError>>()?;
        // 5. Check owner tags and assemble commitments and ciphertexts in order.
        let mut transact_outputs = Vec::with_capacity(slots.len());
        let mut resolved_owner_tags = Vec::with_capacity(slots.len());
        for (slot_index, ((output, owner_tag), slot)) in
            self.outputs.iter().zip(owner_tags).zip(slots).enumerate()
        {
            if slot
                .as_ref()
                .is_some_and(|slot| slot.view_tag != owner_tag.resolved)
            {
                return Err(TransactionError::OwnerTagMismatch { slot_index });
            }
            transact_outputs.push(TransactOutput {
                utxo_hash: output.hash(self.output_tree_id)?,
                owner_tag: owner_tag.tag,
                data: slot.map(|slot| slot.data),
            });
            resolved_owner_tags.push(owner_tag.resolved);
        }
        frame_dummy_outputs(&self.outputs, &mut transact_outputs)?;

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
            cache_accounts: Default::default(),
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
            let resolved = match output.owner_address {
                Some(address) => address.signing_pubkey.confidential_view_tag()?,
                None => output
                    .owner_tag
                    .ok_or(TransactionError::DummyOutputWithoutOwnerTag { slot_index })?,
            };
            // A dummy names a participant and compacts exactly as that
            // participant's real output does; a differently encoded tag would
            // single the dummy out.
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

/// Encrypt one real output to the viewing key its owner address names, `None`
/// for a dummy. A ring-bound output takes the `RingConfidential` scheme byte,
/// every other output `Confidential`.
pub fn seal_output(
    output: &SppProofOutputUtxo,
    slot_index: u32,
    tx_viewing_key: &ViewingKey,
    salt: [u8; SALT_LEN],
) -> Result<Option<MessageData>, TransactionError> {
    let Some(address) = output.owner_address else {
        return Ok(None);
    };
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
            slot_index,
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
    Ok(Some(message))
}

/// Bytes an `OutputDataEncoding::Encrypted` slot spends before its embedded
/// viewing key: the borsh variant tag, the u32 length and the scheme byte.
const ENCRYPTED_OUTPUT_FRAMING_LEN: usize = 1 + 4 + 1;

/// Give every dummy slot the `data` of a real slot: the `Encrypted` encoding,
/// the scheme byte of the slot's ring binding, a fresh embedded viewing key and
/// a random body. A dummy copies the length of a real slot with its ring
/// binding, else of the first real slot, else of the canonical empty payload,
/// so neither framing nor length separates it from a real output. Every real
/// slot must already carry its ciphertext.
pub fn frame_dummy_outputs(
    outputs: &[SppProofOutputUtxo],
    encoded: &mut [TransactOutput],
) -> Result<(), TransactionError> {
    let templates = outputs
        .iter()
        .zip(encoded.iter())
        .enumerate()
        .filter(|(_, (output, _))| !output.is_dummy())
        .map(|(slot_index, (output, encoded))| {
            encoded
                .data
                .as_ref()
                .map(|data| (output.ring_program_id.is_some(), data.len()))
                .ok_or(TransactionError::DummyOutputFraming { slot_index })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (slot_index, (output, encoded)) in outputs.iter().zip(encoded.iter_mut()).enumerate() {
        if !output.is_dummy() {
            continue;
        }
        let in_ring = output.ring_program_id.is_some();
        let template = templates
            .iter()
            .find(|(ring, _)| *ring == in_ring)
            .or_else(|| templates.first());
        let body_len = match template {
            Some((_, encoded_len)) => encoded_len
                .checked_sub(ENCRYPTED_OUTPUT_FRAMING_LEN + P256_PUBKEY_LEN)
                .filter(|len| *len > 0)
                .ok_or(TransactionError::DummyOutputFraming { slot_index })?,
            None => ConfidentialOutputPlaintext {
                asset_id: SOL_ASSET_ID,
                amount: 0,
                blinding: [0u8; 32],
                ring_program_id: output.ring_program_id,
                data: Data::default(),
            }
            .serialize()?
            .len(),
        };
        let scheme = if in_ring {
            EncryptedScheme::RingConfidential
        } else {
            EncryptedScheme::Confidential
        };
        let mut blob = Vec::with_capacity(1 + P256_PUBKEY_LEN + body_len);
        blob.push(scheme.as_byte());
        blob.extend_from_slice(ViewingKey::new().pubkey().as_bytes());
        blob.extend(std::iter::repeat_with(random_salt).flatten().take(body_len));
        encoded.data = Some(
            borsh::to_vec(&OutputDataEncoding::Encrypted(blob))
                .map_err(|error| TransactionError::Deserialize(error.to_string()))?,
        );
    }
    Ok(())
}
