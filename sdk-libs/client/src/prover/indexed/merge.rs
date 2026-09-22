use serde::Serialize;
use zeroize::Zeroizing;
use zolana_hasher::hash_chain::create_hash_chain_4_from_slice;
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::{
            MergeExternalDataHash, MergeProof, MergeTransactIxData,
        },
        tag::MERGE_TRANSACT,
    },
    tree_slot::tree_id_field,
};
use zolana_keypair::{Curve, NullifierKey};
use zolana_transaction::{
    instructions::{
        merge::{
            merge_dummy_nullifier, merge_output_blinding, merge_private_tx_blinding, PreparedMerge,
        },
        transact::PrivateTxHash,
    },
    ProofInputUtxo,
};

use super::{
    hex_field, invalid, scalar_one, transfer::SecretField, IndexedCircuit, IndexedLookup,
    IndexedProof, IndexedProofData, IndexedProofRequest, IndexedTree,
};
use crate::{
    prover::{
        field::right_align_slice, json::MergeOutputParamsJson,
        transact::assembly::assemble_outputs, verify::MergeProofStatement, ProofCompressed,
    },
    ClientError,
};

pub struct IndexedMergePreparation {
    pub merge: PreparedMerge,
    pub nullifier_key: NullifierKey,
}

pub struct PreparedIndexedMerge {
    request: IndexedProofRequest,
    data: MergeTransactIxData,
}

impl IndexedMergePreparation {
    pub fn prepare(self) -> Result<PreparedIndexedMerge, ClientError> {
        let Self {
            merge,
            nullifier_key,
        } = self;
        merge.input_utxo_hashes()?;
        let first = merge
            .inputs
            .first()
            .filter(|input| !input.is_dummy())
            .ok_or(ClientError::NoInputs)?;
        let tree_id = first.tree_id;
        let first_nullifier = first.nullifier()?;
        let nullifier_pk = nullifier_key.pubkey()?;
        if merge.output.blinding != merge_output_blinding(&nullifier_key, &first_nullifier)? {
            return Err(invalid());
        }
        let mut inputs = Vec::new();
        let mut lookups = Vec::new();
        let mut nullifiers = Vec::new();
        let mut input_hashes = Vec::new();
        let mut total = 0u64;
        let mut saw_dummy = false;
        for (index, input) in merge.inputs.iter().enumerate() {
            let dummy = input.is_dummy();
            if !dummy {
                if saw_dummy
                    || input.tree_id != tree_id
                    || input.utxo.owner != merge.signing_pubkey
                    || input.nullifier_key.pubkey()? != nullifier_pk
                    || input.utxo.asset != first.utxo.asset
                    || input.utxo.ring_program_id.is_some()
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
                input.nullifier()?
            };
            let hash = if dummy { [0; 32] } else { utxo.hash()? };
            inputs.push(PreparedMergeInputJson {
                domain: hex_field(&utxo.domain),
                amount: hex_field(&utxo.amount),
                blinding: hex_field(&utxo.blinding),
                ring_data_hash: "0x0",
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
        let outputs = assemble_outputs(std::slice::from_ref(&merge.output), merge.output_tree_id)?;
        let output = outputs.outputs.first().ok_or(ClientError::MissingOutput)?;
        let output_hash = merge.output_hash()?;
        let owner_pk_hash = merge.signing_pubkey.owner_proof_input_hash()?;
        if merge.output.amount != total
            || merge.output.asset != first.utxo.asset
            || output.utxo.ring_data_hash != [0; 32]
            || output.utxo.data_hash != [0; 32]
            || output.utxo.ring_program_id != [0; 32]
            || output.utxo.owner_hash
                != zolana_keypair::hash::owner_hash(&merge.signing_pubkey, &nullifier_pk)?
        {
            return Err(invalid());
        }
        let external = MergeExternalDataHash {
            spp_instruction_discriminator: MERGE_TRANSACT,
            expiry_unix_ts: merge.expiry_unix_ts,
            output_utxo_hash: &output_hash,
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
            owner_pk_hash,
        ];
        let witness = PreparedMergeJson {
            circuit_type: IndexedCircuit::Merge,
            inputs,
            output: MergeOutputParamsJson {
                ring_data_hash: "0x0".to_owned(),
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
            output_ring_data_hash: "0x0",
            ring_program_id: "0x0",
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
            eddsa_owner: matches!(merge.signing_pubkey.curve()?, Curve::Ed25519 | Curve::Pda),
        };
        Ok(PreparedIndexedMerge { request, data })
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

    pub fn finish(mut self, proof: IndexedProof) -> Result<MergeTransactIxData, ClientError> {
        let proof = self.request.validate(proof)?;
        MergeProofStatement {
            n_inputs: self.data.nullifiers.len(),
            public_input_hash: proof.resolution.public_input_hash,
        }
        .verify(&proof.proof)?;
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
    ring_data_hash: &'static str,
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
    output_ring_data_hash: &'static str,
    ring_program_id: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_address::Address;
    use zolana_keypair::{ShieldedKeypair, ShieldedKeypairTrait};
    use zolana_transaction::{
        instructions::{merge::Merge, types::SppProofInputUtxo},
        Data, Utxo,
    };

    #[test]
    fn prepares_both_owner_rails_without_paths() {
        for owner in [
            ShieldedKeypair::new_ed25519().unwrap(),
            ShieldedKeypair::new_p256().unwrap(),
        ] {
            let input = SppProofInputUtxo::new(
                Utxo {
                    owner: owner.signing_pubkey(),
                    asset: Address::default(),
                    amount: 10,
                    blinding: [1; 32],
                    ring_program_id: None,
                    data: Data::default(),
                },
                &owner,
            )
            .in_tree(3);
            let merge = Merge::new(&owner, vec![input])
                .unwrap()
                .with_output_tree_id(4)
                .prepare();
            let expected = merge.dummy_nullifiers(&owner.nullifier_key()).unwrap();
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
            assert_eq!(body["publicInputs"].as_array().unwrap().len(), 7);
        }
    }

    #[test]
    fn rejects_changed_merge_output() {
        let owner = ShieldedKeypair::new_ed25519().unwrap();
        let input = SppProofInputUtxo::new(
            Utxo {
                owner: owner.signing_pubkey(),
                asset: Address::default(),
                amount: 10,
                blinding: [1; 32],
                ring_program_id: None,
                data: Data::default(),
            },
            &owner,
        );
        let mut merge = Merge::new(&owner, vec![input]).unwrap().prepare();
        merge.output.amount += 1;
        assert!(IndexedMergePreparation {
            merge,
            nullifier_key: owner.nullifier_key()
        }
        .prepare()
        .is_err());
    }
}
