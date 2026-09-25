use serde::Serialize;
use zeroize::Zeroizing;
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::{
            MergeExternalDataHash, MergeProof, MergeTransactIxData,
        },
        tag::{MERGE_TRANSACT, RING_MERGE_TRANSACT},
    },
    tree_slot::tree_id_field,
};
use zolana_keypair::{Curve, NullifierKey};
use zolana_transaction::instructions::{
    merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_private_tx_blinding, MergeProofInputs,
    },
    transact::PrivateTxHash,
};

use super::{
    hex_field, invalid, scalar_one, transfer::SecretField, IndexedCircuit, IndexedLookup,
    IndexedProof, IndexedProofData, IndexedProofRequest, IndexedTree,
};
use crate::{
    prover::{
        field::right_align_slice, json::MergeOutputParamsJson,
        transact::assembly::assemble_outputs, verify::MergeProofStatement, ProofCompressed,
        ProofInputUtxo,
    },
    ClientError,
};

pub struct IndexedMergePreparation {
    pub merge: MergeProofInputs,
    pub nullifier_key: NullifierKey,
}

pub struct PreparedIndexedMerge {
    request: IndexedProofRequest,
    data: MergeTransactIxData,
    ring_data_hash: Option<[u8; 32]>,
}

impl IndexedMergePreparation {
    pub fn prepare(self) -> Result<PreparedIndexedMerge, ClientError> {
        self.prepare_with_cache(None)
    }

    pub fn prepare_for_cache(
        self,
        cache: crate::prover::MergeCacheTarget,
    ) -> Result<PreparedIndexedMerge, ClientError> {
        self.prepare_with_cache(Some(cache))
    }

    fn prepare_with_cache(
        self,
        cache: Option<crate::prover::MergeCacheTarget>,
    ) -> Result<PreparedIndexedMerge, ClientError> {
        if cache.is_some_and(|target| {
            usize::from(target.slot) >= zolana_interface::state::cache::CACHE_CAPACITY
        }) {
            return Err(invalid());
        }
        let Self {
            merge,
            nullifier_key,
        } = self;
        merge.input_utxo_hashes()?;
        let ring_hash =
            zolana_transaction::utxo::program_id_proof_input_hash(&merge.ring_program_id)?;
        let ring_data_hash = merge.output_utxo.ring_data_hash.unwrap_or_default();
        let first = merge
            .input_utxos
            .first()
            .filter(|input| !input.is_dummy())
            .ok_or(ClientError::NoInputs)?;
        let tree_id = first.tree_id;
        let first_nullifier = first.nullifier;
        let nullifier_pk = nullifier_key.pubkey()?;
        if merge.output_utxo.blinding != merge_output_blinding(&nullifier_key, &first_nullifier)? {
            return Err(invalid());
        }
        let mut inputs = Vec::new();
        let mut lookups = Vec::new();
        let mut nullifiers = Vec::new();
        let mut input_hashes = Vec::new();
        let mut total = 0u64;
        let mut saw_dummy = false;
        for (index, input) in merge.input_utxos.iter().enumerate() {
            let dummy = input.is_dummy();
            if input.cache_slot.is_some() {
                return Err(invalid());
            }
            if !dummy {
                if saw_dummy
                    || input.tree_id != tree_id
                    || input.utxo.owner != merge.signing_pubkey
                    || input.nullifier_pubkey != nullifier_pk
                    || input.utxo.asset != first.utxo.asset
                    || input.utxo.ring_program_id != merge.ring_program_id
                {
                    return Err(invalid());
                }
                total = total.checked_add(input.utxo.amount).ok_or_else(invalid)?;
            }
            saw_dummy |= dummy;
            let utxo = ProofInputUtxo::try_from(input)?;
            let nullifier = if dummy {
                merge_dummy_nullifier(
                    &nullifier_key,
                    &first_nullifier,
                    u8::try_from(index).map_err(|_| invalid())?,
                )?
            } else {
                input.nullifier
            };
            let commitment = utxo.hash()?;
            if commitment != input.utxo_hash {
                return Err(
                    zolana_transaction::TransactionError::InputCommitmentMismatch { index }.into(),
                );
            }
            if (!dummy
                && nullifier_key.nullifier(&commitment, &input.utxo.blinding)? != input.nullifier)
                || nullifier != input.nullifier
            {
                return Err(ClientError::InputNullifierMismatch { index });
            }
            let hash = if dummy { [0; 32] } else { commitment };
            inputs.push(PreparedMergeInputJson {
                domain: hex_field(&utxo.domain),
                amount: hex_field(&utxo.amount),
                blinding: hex_field(&utxo.blinding),
                ring_data_hash: hex_field(&utxo.ring_data_hash),
                tree_slot: "0x0",
                nullifier: hex_field(&nullifier),
            });
            lookups.push(IndexedLookup {
                tree_slot: 0,
                commitment: (!dummy).then_some(hash),
            });
            input_hashes.push(hash);
            nullifiers.push(nullifier);
        }
        let outputs = assemble_outputs(
            std::slice::from_ref(&merge.output_utxo),
            merge.output_tree_id,
        )?;
        let output = outputs.outputs.first().ok_or(ClientError::MissingOutput)?;
        let output_hash = merge.output_hash()?;
        let owner_pk_hash = merge.signing_pubkey.owner_proof_input_hash()?;
        if merge.output_utxo.amount != total
            || merge.output_utxo.asset != first.utxo.asset
            || (merge.ring_program_id.is_none() && output.utxo.ring_data_hash != [0; 32])
            || output.utxo.data_hash != [0; 32]
            || output.utxo.ring_program_id != ring_hash
            || output.utxo.owner_hash
                != zolana_keypair::hash::owner_hash(&merge.signing_pubkey, &nullifier_pk)?
        {
            return Err(invalid());
        }
        let external = MergeExternalDataHash {
            spp_instruction_discriminator: if merge.ring_program_id.is_some() {
                RING_MERGE_TRANSACT
            } else {
                MERGE_TRANSACT
            },
            expiry_unix_ts: merge.expiry_unix_ts,
            output_utxo_hash: &output_hash,
            cache: cache
                .as_ref()
                .map(|target| (target.address.as_array(), target.slot)),
        }
        .hash()?;
        let private = PrivateTxHash::new(
            &input_hashes,
            &outputs.private_tx_output_hashes,
            &external,
            &merge_private_tx_blinding(&nullifier_key, &first_nullifier)?,
        )
        .hash()?;
        let public_inputs = vec![
            create_hash_chain_4_from_slice(&nullifiers)?,
            output_hash,
            tree_id_field(merge.output_tree_id),
            private,
            external,
            scalar_one(),
            if merge.ring_program_id.is_some() {
                ring_data_hash
            } else {
                owner_pk_hash
            },
            if merge.ring_program_id.is_some() {
                ring_hash
            } else {
                nullifier_pk
            },
        ];
        let witness = PreparedMergeJson {
            circuit_type: if merge.ring_program_id.is_some() {
                IndexedCircuit::MergeRing
            } else {
                IndexedCircuit::Merge
            },
            inputs,
            output: MergeOutputParamsJson {
                ring_data_hash: hex_field(&ring_data_hash),
                hash: hex_field(&output_hash),
            },
            output_tree_id: hex_field(&tree_id_field(merge.output_tree_id)),
            asset: hex_field(&output.utxo.asset),
            owner_pk_hash: hex_field(&owner_pk_hash),
            user_nullifier_pk: hex_field(&nullifier_pk),
            user_nullifier_secret: SecretField(Zeroizing::new(right_align_slice(
                &*nullifier_key.secret(),
            )?)),
            external_data_hash: hex_field(&external),
            private_tx_hash: hex_field(&private),
            allow_dummy_inputs: "0x1",
            output_ring_data_hash: hex_field(&ring_data_hash),
            ring_program_id: hex_field(&ring_hash),
        };
        let request = IndexedProofRequest::new(IndexedProofData {
            witness: Zeroizing::new(serde_json::to_string(&witness).map_err(|_| invalid())?),
            trees: vec![IndexedTree {
                tree: zolana_interface::pda::tree(tree_id).to_bytes().into(),
                id: tree_id,
            }],
            inputs: lookups,
            public_inputs,
        })?;
        let data = MergeTransactIxData {
            expiry_unix_ts: merge.expiry_unix_ts,
            proof: MergeProof {
                a: [0; 32],
                b: [0; 128],
                c: [0; 32],
            },
            output_utxo_hash: output_hash,
            nullifiers,
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            private_tx_hash: private,
            cache_slot: cache.map(|target| target.slot),
            eddsa_owner: matches!(merge.signing_pubkey.curve()?, Curve::Ed25519 | Curve::Pda),
        };
        Ok(PreparedIndexedMerge {
            request,
            data,
            ring_data_hash: merge.ring_program_id.map(|_| ring_data_hash),
        })
    }
}

impl PreparedIndexedMerge {
    pub fn request(&self) -> &IndexedProofRequest {
        &self.request
    }

    #[must_use]
    pub fn with_min_context_slot(mut self, slot: u64) -> Self {
        self.request = self.request.with_min_context_slot(slot);
        self
    }

    pub fn finish(self, proof: IndexedProof) -> Result<MergeTransactIxData, ClientError> {
        if self.ring_data_hash.is_some() {
            return Err(invalid());
        }
        self.complete(proof)
    }

    pub fn finish_ring(
        self,
        proof: IndexedProof,
    ) -> Result<
        zolana_interface::instruction::instruction_data::merge_ring::MergeRingIxData,
        ClientError,
    > {
        let output_ring_data_hash = self.ring_data_hash.ok_or_else(invalid)?;
        Ok(
            zolana_interface::instruction::instruction_data::merge_ring::MergeRingIxData {
                output_ring_data_hash,
                merge: self.complete(proof)?,
            },
        )
    }

    fn complete(mut self, proof: IndexedProof) -> Result<MergeTransactIxData, ClientError> {
        let proof = self.request.validate(proof)?;
        let statement = MergeProofStatement {
            n_inputs: self.data.nullifiers.len(),
            public_input_hash: proof.resolution.public_input_hash,
        };
        if self.ring_data_hash.is_some() {
            statement.verify_ring(&proof.proof)?;
        } else {
            statement.verify(&proof.proof)?;
        }
        let context = proof.resolution.trees.first().ok_or_else(invalid)?.context;
        self.data.utxo_tree_root_index = context.utxo_tree_root_index;
        self.data.nullifier_tree_root_index = context.nullifier_tree_root_index;
        self.data.proof = ProofCompressed::try_from(proof.proof)?.to_merge_proof()?;
        Ok(self.data)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedMergeInputJson {
    domain: String,
    amount: String,
    blinding: String,
    ring_data_hash: String,
    tree_slot: &'static str,
    nullifier: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedMergeJson {
    circuit_type: IndexedCircuit,
    inputs: Vec<PreparedMergeInputJson>,
    output: MergeOutputParamsJson,
    output_tree_id: String,
    asset: String,
    owner_pk_hash: String,
    user_nullifier_pk: String,
    user_nullifier_secret: SecretField,
    external_data_hash: String,
    private_tx_hash: String,
    allow_dummy_inputs: &'static str,
    output_ring_data_hash: String,
    ring_program_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_keypair::{ShieldedKeypair, ShieldedKeypairTrait};
    use zolana_transaction::{instructions::merge::MergeTransaction, Data, Mint, Utxo, WalletUtxo};

    fn input(owner: &ShieldedKeypair) -> WalletUtxo {
        let utxo = Utxo {
            owner: owner.signing_pubkey(),
            asset: Mint::SOL,
            amount: 10,
            blinding: [1; 32],
            ring_program_id: None,
            data: Data::default(),
        };
        let nullifier_pubkey = owner.nullifier_key.pubkey().unwrap();
        let utxo_hash = utxo.hash(&nullifier_pubkey, &[0; 32], &[0; 32], 3).unwrap();
        WalletUtxo {
            nullifier: owner
                .nullifier_key
                .nullifier(&utxo_hash, &utxo.blinding)
                .unwrap(),
            utxo,
            nullifier_pubkey,
            utxo_hash,
            data_hash: None,
            ring_data_hash: None,
            tree_id: 3,
            leaf_index: 0,
            slot: 0,
            tx_signature: Default::default(),
            slot_index: 0,
        }
    }

    #[test]
    fn prepares_both_owner_rails_without_paths() {
        for owner in [
            ShieldedKeypair::new_ed25519().unwrap(),
            ShieldedKeypair::new_p256().unwrap(),
        ] {
            let merge = MergeTransaction::new(vec![input(&owner)])
                .unwrap()
                .with_output_tree_id(4)
                .encrypt(&owner)
                .unwrap();
            let expected = merge.dummy_nullifiers();
            let output = merge.output_hash().unwrap();
            let prepared = IndexedMergePreparation {
                merge,
                nullifier_key: owner.nullifier_key(),
            }
            .prepare()
            .unwrap();
            assert_eq!(prepared.data.output_utxo_hash, output);
            assert_eq!(&prepared.data.nullifiers[1..], expected);
            assert_eq!(prepared.request.input_trees()[0].id, 3);
            let body: serde_json::Value =
                serde_json::from_str(&prepared.request.body().unwrap()).unwrap();
            assert!(body["prepared"].get("treeSlots").is_none());
            assert!(body["prepared"]["inputs"][0]
                .get("statePathElements")
                .is_none());
            assert_eq!(body["inputs"][1]["commitment"], serde_json::Value::Null);
            assert_eq!(body["publicInputs"].as_array().unwrap().len(), 8);
            assert_eq!(body["publicInputs"][7], body["prepared"]["userNullifierPk"]);
        }
    }

    #[test]
    fn rejects_changed_merge_input_commitments_and_nullifiers() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        for index in [0, 1] {
            let mut merge = MergeTransaction::new(vec![input(&owner)])
                .unwrap()
                .encrypt(&owner)
                .unwrap();
            merge.input_utxos[index].utxo_hash[31] ^= 1;
            assert!(matches!(
                IndexedMergePreparation {
                    merge,
                    nullifier_key: owner.nullifier_key(),
                }
                .prepare(),
                Err(ClientError::Transaction(
                    zolana_transaction::TransactionError::InputCommitmentMismatch { .. }
                ))
            ));
            let mut merge = MergeTransaction::new(vec![input(&owner)])
                .unwrap()
                .encrypt(&owner)
                .unwrap();
            merge.input_utxos[index].nullifier[31] ^= 1;
            assert!(IndexedMergePreparation {
                merge,
                nullifier_key: owner.nullifier_key(),
            }
            .prepare()
            .is_err());
        }
    }

    #[test]
    fn rejects_changed_merge_output() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let mut merge = MergeTransaction::new(vec![input(&owner)])
            .unwrap()
            .encrypt(&owner)
            .unwrap();
        merge.output_utxo.amount += 1;
        assert!(IndexedMergePreparation {
            merge,
            nullifier_key: owner.nullifier_key()
        }
        .prepare()
        .is_err());
    }
}
