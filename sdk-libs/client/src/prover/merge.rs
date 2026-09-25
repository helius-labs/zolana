use num_bigint::BigUint;
use solana_address::Address;
use zolana_event::MessageData;
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            merge_ring::MergeRingIxData,
            merge_transact::{MergeExternalDataHash, MergeProof, MergeTransactIxData},
        },
        tag::{MERGE_TRANSACT, RING_MERGE_TRANSACT},
    },
    state::cache::CACHE_CAPACITY,
    tree_slot::{tree_id_field, tree_slots_hash_chain},
};
use zolana_keypair::{Curve, NullifierKey};
use zolana_transaction::{
    instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_private_tx_blinding, MergeProofInputs,
        MERGE_SUPPORTED_INPUT_COUNTS,
    },
    utxo::program_id_proof_input_hash,
};

use crate::{
    error::ClientError,
    prover::{
        field::{be, right_align, right_align_slice},
        transact::{
            assembly::{assemble_inputs, assemble_outputs, private_tx_hash, OwnerMode},
            witness::{attach_input_proofs, SpendProof},
        },
        MergeInputs, TreeSlotFields,
    },
    rpc::NonInclusionProof,
};

pub struct MergeProver {
    pub transaction: MergeProofInputs,
    pub nullifier_key: NullifierKey,
    pub proofs: Vec<SpendProof>,
    pub dummy_nullifier_proofs: Vec<NonInclusionProof>,
    pub cache: Option<MergeCacheTarget>,
}

/// The cache slot a merge writes its output to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeCacheTarget {
    pub address: Address,
    pub slot: u8,
}

#[derive(Debug, Clone)]
pub struct MergeProofResult {
    pub inputs: MergeInputs,
    pub public_input_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    /// Root cache indexes shared by all input slots.
    pub utxo_tree_root_index: u16,
    pub nullifier_tree_root_index: u16,
    pub output_hash: [u8; 32],
    pub private_tx_hash: [u8; 32],
    /// Recomputed on-chain from the instruction; surfaced so the caller need not
    /// re-derive it.
    pub external_data_hash: [u8; 32],
    pub expiry_unix_ts: u64,
    /// True when the owner is a Solana (ed25519) signer, so `merge_transact` derives
    /// `signing_pk_field` from the registry account owner instead of `owner_p256`.
    pub eddsa_owner: bool,
    pub cache_slot: Option<u8>,
    pub ring_program_id: Option<Address>,
    pub output_ring_data_hash: [u8; 32],
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    pub output_data: MessageData,
}

impl MergeProofResult {
    /// Assemble the `merge_transact` instruction data from this proof result and
    /// the proof (`ProofCompressed::to_merge_proof`). The caller passes the
    /// result to the `MergeTransact` builder with the tree / protocol_config /
    /// user_record accounts.
    pub fn instruction_data(&self, proof: MergeProof) -> MergeTransactIxData {
        MergeTransactIxData {
            expiry_unix_ts: self.expiry_unix_ts,
            proof,
            output_utxo_hash: self.output_hash,
            nullifiers: self.nullifiers.clone(),
            utxo_tree_root_index: self.utxo_tree_root_index,
            nullifier_tree_root_index: self.nullifier_tree_root_index,
            private_tx_hash: self.private_tx_hash,
            eddsa_owner: self.eddsa_owner,
            cache_slot: self.cache_slot,
        }
    }

    /// Assemble the `merge_ring` instruction data: the same `merge_transact`
    /// body wrapped in a [`MergeRingIxData`] with the output `ring_data_hash`
    /// the ring program selected. The caller passes the result to the
    /// `MergeRing` builder with the tree / ring_config accounts.
    pub fn ring_instruction_data(&self, proof: MergeProof) -> MergeRingIxData {
        MergeRingIxData {
            output_ring_data_hash: self.output_ring_data_hash,
            merge: self.instruction_data(proof),
        }
    }
}

impl MergeProver {
    pub fn build(self) -> Result<MergeProofResult, ClientError> {
        let tx = &self.transaction;
        let n_inputs = tx.input_utxos.len();
        if !MERGE_SUPPORTED_INPUT_COUNTS.contains(&n_inputs) {
            return Err(ClientError::UnsupportedShape {
                n_in: n_inputs,
                n_out: 1,
            });
        }
        let first = tx
            .input_utxos
            .first()
            .filter(|input| !input.is_dummy())
            .ok_or(ClientError::NoInputs)?;
        let first_nullifier = first.nullifier;
        let nullifier_pubkey = self.nullifier_key.pubkey()?;
        let mut total = 0u64;
        tx.input_utxo_hashes()?;
        for (index, input) in tx.input_utxos.iter().enumerate() {
            if input.is_dummy() {
                let slot = u8::try_from(index).map_err(|_| ClientError::TooManyInputs {
                    got: n_inputs,
                    max: usize::from(u8::MAX),
                })?;
                if input.nullifier
                    != merge_dummy_nullifier(&self.nullifier_key, &first_nullifier, slot)?
                {
                    return Err(ClientError::InputNullifierMismatch { index });
                }
                continue;
            }
            if input.utxo.owner != tx.signing_pubkey {
                return Err(ClientError::MergeSigningKeyMismatch);
            }
            if input.nullifier_pubkey != nullifier_pubkey {
                return Err(ClientError::MergeNullifierKeyMismatch);
            }
            if input.utxo.ring_program_id != tx.ring_program_id {
                return Err(ClientError::InputRingProgramMismatch { index });
            }
            if input.utxo.asset != first.utxo.asset {
                return Err(ClientError::MergeInputAssetMismatch { index });
            }
            if input.nullifier
                != self
                    .nullifier_key
                    .nullifier(&input.utxo_hash, &input.utxo.blinding)?
            {
                return Err(ClientError::InputNullifierMismatch { index });
            }
            total = total
                .checked_add(input.utxo.amount)
                .ok_or(ClientError::SelectedBalanceOverflow)?;
        }
        let output = &tx.output_utxo;
        if output.is_dummy()
            || output.asset != first.utxo.asset
            || output.amount != total
            || output.ring_program_id != tx.ring_program_id
            || output.data_hash.is_some()
            || (tx.ring_program_id.is_none() && output.ring_data_hash.is_some())
            || !output.owner_address.is_some_and(|owner| {
                owner.signing_pubkey == tx.signing_pubkey
                    && owner.nullifier_pubkey == nullifier_pubkey
            })
        {
            return Err(ClientError::MergeOutputMismatch);
        }
        if output.blinding != merge_output_blinding(&self.nullifier_key, &first_nullifier)? {
            return Err(ClientError::OutputBlindingMismatch { index: 0 });
        }
        let MergeProofInputs {
            input_utxos,
            output_utxo,
            expiry_unix_ts,
            signing_pubkey,
            output_tree_id,
            ring_program_id,
            tx_viewing_pk,
            salt,
            output_data,
        } = self.transaction;
        let inputs = attach_input_proofs(input_utxos, &self.proofs, &self.dummy_nullifier_proofs)?;
        let assembled_inputs = assemble_inputs(&inputs, &OwnerMode::Merge)?;
        let input_tree_context = assembled_inputs.single_tree_context()?;
        let assembled_outputs =
            assemble_outputs(std::slice::from_ref(&output_utxo), output_tree_id)?;
        let output_hash = *assembled_outputs
            .output_hashes
            .first()
            .ok_or(ClientError::MissingOutput)?;
        let cache_slot = match self.cache.as_ref() {
            Some(target) if usize::from(target.slot) < CACHE_CAPACITY => Some(target.slot),
            Some(_) => return Err(ShieldedPoolError::InvalidCacheSlot.into()),
            None => None,
        };
        let external_data_hash = MergeExternalDataHash {
            spp_instruction_discriminator: if ring_program_id.is_some() {
                RING_MERGE_TRANSACT
            } else {
                MERGE_TRANSACT
            },
            expiry_unix_ts,
            output_utxo_hash: &output_hash,
            cache: self
                .cache
                .as_ref()
                .map(|target| target.address.as_array())
                .zip(cache_slot),
        }
        .hash()?;
        let private_tx_blinding = merge_private_tx_blinding(&self.nullifier_key, &first_nullifier)?;
        let private_tx = private_tx_hash(
            &assembled_inputs,
            &assembled_outputs,
            &external_data_hash,
            &private_tx_blinding,
        )?;
        let user_signing_pk_hash = signing_pubkey.owner_proof_input_hash()?;
        let mut elements = vec![
            create_hash_chain_4_from_slice(&assembled_inputs.nullifiers)?,
            output_hash,
            tree_slots_hash_chain(&assembled_inputs.tree_slots)?,
            tree_id_field(output_tree_id),
            private_tx,
            external_data_hash,
            right_align(&[1u8]),
        ];
        let output_ring_data_hash = output_utxo.ring_data_hash.unwrap_or_default();
        let ring_hash = program_id_proof_input_hash(&ring_program_id)?;
        if ring_program_id.is_some() {
            elements.extend([output_ring_data_hash, ring_hash]);
        } else {
            // Bind both halves of the UTXO owner to the registry, so another
            // nullifier key cannot manufacture a merge for this signing identity.
            elements.extend([user_signing_pk_hash, nullifier_pubkey]);
        }
        let public_input_hash = create_hash_chain_4_from_slice(&elements)?;
        let eddsa_owner = match signing_pubkey.curve()? {
            Curve::Ed25519 | Curve::Pda => true,
            Curve::P256 => false,
        };
        let user_nullifier_secret = right_align_slice(&*self.nullifier_key.secret())?;
        let output = assembled_outputs
            .outputs
            .into_iter()
            .next()
            .ok_or(ClientError::MissingOutput)?;
        let inputs = MergeInputs {
            inputs: assembled_inputs.inputs,
            output,
            tree_slots: TreeSlotFields::encode_all(&assembled_inputs.tree_slots),
            output_tree_id: BigUint::from(output_tree_id),
            owner_pk_hash: be(&user_signing_pk_hash),
            user_nullifier_pk: be(&nullifier_pubkey),
            user_nullifier_secret: be(&user_nullifier_secret),
            external_data_hash: be(&external_data_hash),
            private_tx_hash: be(&private_tx),
            allow_dummy_inputs: BigUint::from(1u8),
            public_input_hash: be(&public_input_hash),
            output_ring_data_hash: be(&output_ring_data_hash),
            ring_program_id: be(&ring_hash),
        };
        Ok(MergeProofResult {
            inputs,
            public_input_hash,
            nullifiers: assembled_inputs.nullifiers,
            utxo_tree_root_index: input_tree_context.utxo_tree_root_index,
            nullifier_tree_root_index: input_tree_context.nullifier_tree_root_index,
            output_hash,
            private_tx_hash: private_tx,
            external_data_hash,
            expiry_unix_ts,
            eddsa_owner,
            cache_slot,
            ring_program_id,
            output_ring_data_hash,
            tx_viewing_pk,
            salt,
            output_data,
        })
    }
}
