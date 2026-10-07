use zolana_keypair::{ShieldedAddress, ViewingKey};

use super::{
    inputs::{pad_with_compact, validate_merge_owner},
    MergeOutputEnvelope, MergeProofInputs, MergeTransaction,
};
use crate::{
    error::TransactionError,
    keys::{DeriveRequest, ShieldedKeys},
    utxo::SppProofInputUtxo,
    SppProofOutputUtxo,
};

pub enum MergeBlindingSource<'a> {
    Envelope { ephemeral: &'a ViewingKey },
    Derived { output_blinding: [u8; 32] },
}

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
        let ring = self.ring_program_id.is_some();
        let mut requests = Vec::new();
        if ring {
            requests.push(DeriveRequest::MergeOutputBlinding { first_nullifier });
        }
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
        let derived = shielded_keys.derive(&requests)?;
        if derived.len() != requests.len() {
            return Err(TransactionError::IncompleteDerivation {
                got: derived.len(),
                want: requests.len(),
            });
        }
        if ring {
            let got = derived.len();
            let (&output_blinding, dummy_nullifiers) = derived
                .split_first()
                .ok_or(TransactionError::IncompleteDerivation { got, want: 1 })?;
            self.encrypt_with(
                &sender,
                MergeBlindingSource::Derived { output_blinding },
                dummy_nullifiers,
            )
        } else {
            let ephemeral = ViewingKey::new();
            self.encrypt_with(
                &sender,
                MergeBlindingSource::Envelope {
                    ephemeral: &ephemeral,
                },
                &derived,
            )
        }
    }

    pub fn encrypt_with(
        self,
        sender: &ShieldedAddress,
        blinding: MergeBlindingSource<'_>,
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
        let envelope = match (ring_program_id, blinding) {
            (None, MergeBlindingSource::Envelope { ephemeral }) => {
                let envelope = MergeOutputEnvelope {
                    recipient: sender.viewing_pubkey,
                    ephemeral: ephemeral.clone(),
                };
                output_utxo.blinding = envelope
                    .seal(output_utxo.amount, &output_utxo.asset.asset)?
                    .output_blinding;
                Some(envelope)
            }
            (Some(ring_program_id), MergeBlindingSource::Derived { output_blinding }) => {
                output_utxo = match output_ring_data_hash {
                    Some(ring_data_hash) => {
                        output_utxo.with_ring_data_hash(ring_program_id, ring_data_hash)
                    }
                    None => output_utxo.with_ring_program_id(ring_program_id),
                };
                output_utxo.blinding = output_blinding;
                None
            }
            _ => return Err(TransactionError::MergeBlindingRailMismatch),
        };
        let mut input_utxos = inputs.into_iter().map(SppProofInputUtxo::from).collect();
        pad_with_compact(
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
            envelope,
        })
    }
}
