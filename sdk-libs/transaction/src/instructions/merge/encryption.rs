use borsh::BorshDeserialize;
use zolana_event::OutputDataEncoding;
use zolana_keypair::{random_salt, ShieldedAddress, ViewingKey};

use super::{
    inputs::{pad_with_dummies, validate_merge_owner},
    MergeProofInputs, MergeTransaction,
};
use crate::{
    error::TransactionError,
    keys::{DeriveRequest, ShieldedKeys, TransactionKeyRequest},
    serialization::{
        confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
        UtxoSerialization,
    },
    utxo::SppProofInputUtxo,
    EncryptedScheme, SppProofOutputUtxo,
};

impl MergeTransaction {
    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        shielded_keys: &K,
    ) -> Result<MergeProofInputs, TransactionError> {
        let sender = shielded_keys.address()?;
        let first_nullifier = self
            .inputs
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier;
        let mut requests = vec![DeriveRequest::MergeOutputBlinding { first_nullifier }];
        for slot in self.inputs.len()..self.validated_inputs.padded_input_count {
            let slot_index = u8::try_from(slot).map_err(|_| TransactionError::TooManyInputs {
                got: slot + 1,
                max: usize::from(u8::MAX),
            })?;
            requests.push(DeriveRequest::MergeDummyNullifier {
                first_nullifier,
                slot_index,
            });
        }
        let blindings = shielded_keys.derive(&requests)?;
        if blindings.len() != requests.len() {
            return Err(TransactionError::IncompleteDerivation {
                got: blindings.len(),
                want: requests.len(),
            });
        }
        let got = blindings.len();
        let mut derived = blindings.into_iter();
        let output_blinding = derived
            .next()
            .ok_or(TransactionError::IncompleteDerivation { got, want: 1 })?;
        let tx_viewing_keys = shielded_keys.transaction_keys(&[TransactionKeyRequest {
            viewing_pubkey: sender.viewing_pubkey,
            first_nullifier,
        }])?;
        let got = tx_viewing_keys.len();
        let tx_viewing_key = tx_viewing_keys
            .into_iter()
            .next()
            .ok_or(TransactionError::IncompleteDerivation { got, want: 1 })?;
        self.encrypt_with_viewing_key(
            &sender,
            &tx_viewing_key,
            output_blinding,
            &derived.collect::<Vec<_>>(),
        )
    }

    /// `dummy_nullifiers` contains final nullifiers in appended slot order.
    pub fn encrypt_with_viewing_key(
        self,
        sender: &ShieldedAddress,
        tx_viewing_key: &ViewingKey,
        output_blinding: [u8; 32],
        dummy_nullifiers: &[[u8; 32]],
    ) -> Result<MergeProofInputs, TransactionError> {
        let Self {
            inputs,
            validated_inputs,
            expiry_unix_ts,
            output_tree_id,
            ring_program_id,
            output_ring_data_hash,
        } = self;
        validate_merge_owner(sender, &inputs)?;
        let mut output_utxo =
            SppProofOutputUtxo::new(validated_inputs.asset, validated_inputs.total, *sender)?;
        if let Some(ring_program_id) = ring_program_id {
            output_utxo = match output_ring_data_hash {
                Some(ring_data_hash) => {
                    output_utxo.with_ring_data_hash(ring_program_id, ring_data_hash)
                }
                None => output_utxo.with_ring_program_id(ring_program_id),
            };
        }
        output_utxo.blinding = output_blinding;
        let salt = random_salt();
        let mut output_data = Confidential::encode_plaintext(
            &ConfidentialOutputPlaintext {
                asset_id: output_utxo.asset.asset_id,
                amount: output_utxo.amount,
                blinding: output_utxo.blinding,
                ring_program_id: output_utxo.ring_program_id,
                data: output_utxo.data.clone(),
            },
            sender.signing_pubkey.confidential_view_tag()?,
            &ConfidentialEncode {
                tx: tx_viewing_key.clone(),
                recipient_pubkey: sender.viewing_pubkey,
                salt,
                slot_index: 0,
            },
        )?;
        if ring_program_id.is_some() {
            let OutputDataEncoding::Encrypted(mut blob) =
                OutputDataEncoding::try_from_slice(&output_data.data)
                    .map_err(|error| TransactionError::Deserialize(error.to_string()))?
            else {
                return Err(TransactionError::BadDiscriminator(
                    EncryptedScheme::Confidential.as_byte(),
                ));
            };
            *blob.first_mut().ok_or(TransactionError::MissingOutput)? =
                EncryptedScheme::RingConfidential.as_byte();
            output_data.data = borsh::to_vec(&OutputDataEncoding::Encrypted(blob))
                .map_err(|error| TransactionError::Deserialize(error.to_string()))?;
        }
        let mut input_utxos = inputs.into_iter().map(SppProofInputUtxo::from).collect();
        pad_with_dummies(
            &mut input_utxos,
            validated_inputs.padded_input_count,
            dummy_nullifiers,
        )?;
        Ok(MergeProofInputs {
            input_utxos,
            output_utxo,
            expiry_unix_ts,
            signing_pubkey: sender.signing_pubkey,
            output_tree_id,
            ring_program_id,
            tx_viewing_pk: *tx_viewing_key.pubkey().as_bytes(),
            salt,
            output_data,
        })
    }
}
