use zolana_keypair::{random_salt, viewing_key::Salt, ShieldedAddress};

use super::{
    inputs::{pad_with_compact, validate_merge_owner},
    MergeOutputPlaintext, MergeProofInputs, MergeTransaction,
};
use crate::{
    error::TransactionError,
    keys::{DeriveRequest, ShieldedKeys},
    utxo::SppProofInputUtxo,
    SppProofOutputUtxo,
};

/// The nullifier-secret derivations a merge output needs, answered by
/// [`ShieldedKeys::derive`].
#[derive(Clone, Copy, Debug)]
pub struct MergeOutputSecrets {
    pub blinding: [u8; 32],
    pub key: [u8; 32],
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
        let mut requests = vec![
            DeriveRequest::MergeOutputBlinding { first_nullifier },
            DeriveRequest::MergeOutputKey { first_nullifier },
        ];
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
        let Some(([blinding, key], dummy_nullifiers)) = derived.split_first_chunk::<2>() else {
            return Err(TransactionError::IncompleteDerivation {
                got: derived.len(),
                want: requests.len(),
            });
        };
        self.encrypt_with_derived(
            &sender,
            MergeOutputSecrets {
                blinding: *blinding,
                key: *key,
            },
            random_salt(),
            dummy_nullifiers,
        )
    }

    /// `dummy_nullifiers` holds each padding slot's derived merge dummy
    /// nullifier in slot order; the compact slot proves it absent. `salt` must
    /// be fresh per proof.
    pub fn encrypt_with_derived(
        self,
        sender: &ShieldedAddress,
        secrets: MergeOutputSecrets,
        salt: Salt,
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
        output_utxo.blinding = secrets.blinding;
        let output_ciphertext = MergeOutputPlaintext {
            amount: output_utxo.amount,
            mint: output_utxo.asset.asset,
        }
        .encrypt(&secrets.key, &salt)?;
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
            output_ciphertext_salt: salt,
            output_ciphertext,
        })
    }
}
