use num_bigint::BigUint;
use serde::Serialize;
use zolana_hasher::hash_chain::create_hash_chain_from_slice;
use zolana_interface::{
    instruction::instruction_data::{
        merge_chain_transact::MergeChainTransactIxData,
        merge_transact::{MergeExternalDataHash, MergeProof, MERGE_INPUT_COUNT},
    },
    verifying_keys::{merge_chain::merge_chain_chained_slots, Bsb22Commitment},
};
use zolana_transaction::instructions::transact::PrivateTxHash;

use crate::{
    error::ClientError,
    prover::{
        field::right_align_slice,
        json::{hex64, proof_json, ProofJson},
        merge::MergeProofResult,
        proof::Proof,
    },
};

/// One proved merge and the per-slot values its public input folds. The prover
/// refolds them, so a leg that misreports a slot fails to prove rather than
/// chaining silently.
///
/// A chained slot carries the output hash of the leg below it in
/// `input_utxo_hashes`, and its `utxo_tree_roots` and `nullifier_tree_roots`
/// entries are whatever the merge proof used. Neither reaches the chain.
#[derive(Debug, Clone)]
pub struct MergeChainLeg {
    pub proof: Proof,
    pub nullifiers: [[u8; 32]; MERGE_INPUT_COUNT],
    pub utxo_tree_roots: [[u8; 32]; MERGE_INPUT_COUNT],
    pub nullifier_tree_roots: [[u8; 32]; MERGE_INPUT_COUNT],
    pub input_utxo_hashes: [[u8; 32]; MERGE_INPUT_COUNT],
    pub output_utxo_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
    pub allow_dummy_inputs: [u8; 32],
    pub signing_pk_field: [u8; 32],
}

/// Inputs for one merge chain proof request. `levels` gives the legs per level,
/// bottom level first, and `legs` runs in the same order.
#[derive(Debug, Clone)]
pub struct MergeChainInputs {
    pub levels: Vec<u8>,
    pub legs: Vec<MergeChainLeg>,
}

#[derive(Debug, Serialize)]
struct LegJson {
    proof: ProofJson,
    nullifiers: Vec<String>,
    #[serde(rename = "utxoTreeRoots")]
    utxo_tree_roots: Vec<String>,
    #[serde(rename = "nullifierTreeRoots")]
    nullifier_tree_roots: Vec<String>,
    #[serde(rename = "inputUtxoHashes")]
    input_utxo_hashes: Vec<String>,
    #[serde(rename = "outputUtxoHash")]
    output_utxo_hash: String,
    #[serde(rename = "externalDataHash")]
    external_data_hash: String,
    #[serde(rename = "allowDummyInputs")]
    allow_dummy_inputs: String,
    #[serde(rename = "signingPkHash")]
    signing_pk_hash: String,
}

#[derive(Debug, Serialize)]
struct MergeChainParamsJson {
    #[serde(rename = "circuitType")]
    circuit_type: &'static str,
    levels: Vec<u8>,
    legs: Vec<LegJson>,
}

fn hex64_all(values: &[[u8; 32]; MERGE_INPUT_COUNT]) -> Vec<String> {
    values.iter().map(|value| hex64(value)).collect()
}

/// [`Proof::a`] arrives negated for the on-chain verifier. The recursive
/// verifier does not negate, so A is restored to the point the prover produced
/// before it is chained.
pub(crate) fn to_json_merge_chain(inputs: &MergeChainInputs) -> String {
    let params = MergeChainParamsJson {
        circuit_type: "merge-chain",
        levels: inputs.levels.clone(),
        legs: inputs
            .legs
            .iter()
            .map(|leg| LegJson {
                proof: proof_json(&leg.proof),
                nullifiers: hex64_all(&leg.nullifiers),
                utxo_tree_roots: hex64_all(&leg.utxo_tree_roots),
                nullifier_tree_roots: hex64_all(&leg.nullifier_tree_roots),
                input_utxo_hashes: hex64_all(&leg.input_utxo_hashes),
                output_utxo_hash: hex64(&leg.output_utxo_hash),
                external_data_hash: hex64(&leg.external_data_hash),
                allow_dummy_inputs: hex64(&leg.allow_dummy_inputs),
                signing_pk_hash: hex64(&leg.signing_pk_field),
            })
            .collect(),
    };
    serde_json::to_string(&params).expect("merge chain request serialization is infallible")
}

/// The external data hash every leg of a chain folds. It names this
/// instruction, the transaction's expiry, and the output the pool inserts, so a
/// leg whose own output stays inside the proof is still bound to the
/// transaction that settles it.
pub fn merge_chain_external_data_hash(
    expiry_unix_ts: u64,
    output_utxo_hash: &[u8; 32],
) -> Result<[u8; 32], ClientError> {
    Ok(MergeExternalDataHash {
        spp_instruction_discriminator: zolana_interface::instruction::tag::MERGE_CHAIN_TRANSACT,
        expiry_unix_ts,
        output_utxo_hash,
    }
    .hash()?)
}

/// One proved leg of a chain. It holds the merge witness result and its proof.
#[derive(Debug, Clone)]
pub struct MergeChainLegProof {
    pub result: MergeProofResult,
    pub proof: Proof,
}

/// The legs of one chain, bottom level first, which is the order the outer
/// circuit verifies them in.
///
/// A chained slot is one the level below feeds. It takes the high slots of a
/// leg, so the tree-backed inputs keep a contiguous low range and the
/// instruction's per-slot vectors stay in leg then slot order.
#[derive(Debug, Clone)]
pub struct MergeChain {
    pub levels: Vec<u8>,
    pub legs: Vec<MergeChainLegProof>,
    /// The owner identity every leg proved against. The pool binds it to the
    /// registry record once for the whole chain.
    pub signing_pk_field: [u8; 32],
}

impl MergeChain {
    /// The chain proof request. The prover refolds every leg's public input
    /// from these values, so a misreported slot fails to prove.
    pub fn proof_inputs(&self) -> Result<MergeChainInputs, ClientError> {
        self.chained_slots()?;
        let mut legs = Vec::with_capacity(self.legs.len());
        for leg in &self.legs {
            let inputs = self.leg_inputs(leg)?;
            // The prover refolds a leg from these values and proves against the
            // result. A mismatch here would otherwise surface as an unsatisfied
            // constraint inside a pairing, naming nothing.
            if leg_public_input(&inputs)? != leg.result.public_input_hash {
                return Err(self.unsupported());
            }
            legs.push(inputs);
        }
        Ok(MergeChainInputs {
            levels: self.levels.clone(),
            legs,
        })
    }

    /// The `merge_chain_transact` payload. Only tree-backed slots reach the
    /// wire. A chained slot spends a UTXO no tree holds, so it has no nullifier
    /// to queue and no root to resolve.
    pub fn instruction_data(
        &self,
        proof: MergeProof,
        bsb22_commitment: Bsb22Commitment,
    ) -> Result<MergeChainTransactIxData, ClientError> {
        let chained = self.chained_slots()?;
        let top = self.legs.last().ok_or_else(|| self.unsupported())?;

        let mut nullifiers = Vec::new();
        let mut utxo_tree_root_index = Vec::new();
        let mut nullifier_tree_root_index = Vec::new();
        for (leg, &chained) in self.legs.iter().zip(chained.iter()) {
            let tree_backed = MERGE_INPUT_COUNT - usize::from(chained);
            nullifiers.extend_from_slice(&leg.result.nullifiers[..tree_backed]);
            utxo_tree_root_index
                .extend_from_slice(&leg.result.utxo_tree_root_indices[..tree_backed]);
            nullifier_tree_root_index
                .extend_from_slice(&leg.result.nullifier_tree_root_indices[..tree_backed]);
        }

        Ok(MergeChainTransactIxData {
            expiry_unix_ts: top.result.expiry_unix_ts,
            proof,
            bsb22_commitment,
            output_utxo_hash: top.result.output_hash,
            eddsa_owner: top.result.eddsa_owner,
            levels: self.levels.clone(),
            private_tx_hashes: self
                .legs
                .iter()
                .map(|leg| leg.result.private_tx_hash)
                .collect(),
            nullifiers,
            utxo_tree_root_index,
            nullifier_tree_root_index,
        })
    }

    fn chained_slots(&self) -> Result<Vec<u8>, ClientError> {
        let chained =
            merge_chain_chained_slots(&self.levels).filter(|c| c.len() == self.legs.len());
        chained.ok_or_else(|| self.unsupported())
    }

    fn unsupported(&self) -> ClientError {
        ClientError::UnsupportedMergeChain {
            levels: self.levels.clone(),
            legs: self.legs.len(),
        }
    }

    fn leg_inputs(&self, leg: &MergeChainLegProof) -> Result<MergeChainLeg, ClientError> {
        let slots = &leg.result.inputs.inputs;
        if slots.len() != MERGE_INPUT_COUNT
            || leg.result.nullifiers.len() != MERGE_INPUT_COUNT
            || leg.result.input_hashes.len() != MERGE_INPUT_COUNT
        {
            return Err(self.unsupported());
        }
        let mut inputs = MergeChainLeg {
            proof: leg.proof,
            nullifiers: [[0u8; 32]; MERGE_INPUT_COUNT],
            utxo_tree_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
            nullifier_tree_roots: [[0u8; 32]; MERGE_INPUT_COUNT],
            input_utxo_hashes: [[0u8; 32]; MERGE_INPUT_COUNT],
            output_utxo_hash: leg.result.output_hash,
            external_data_hash: leg.result.external_data_hash,
            allow_dummy_inputs: field_be(&leg.result.inputs.allow_dummy_inputs)?,
            signing_pk_field: self.signing_pk_field,
        };
        for (slot, input) in slots.iter().enumerate() {
            inputs.nullifiers[slot] = leg.result.nullifiers[slot];
            inputs.input_utxo_hashes[slot] = leg.result.input_hashes[slot];
            inputs.utxo_tree_roots[slot] = field_be(&input.utxo_tree_root)?;
            inputs.nullifier_tree_roots[slot] = field_be(&input.nullifier_tree_root)?;
        }
        Ok(inputs)
    }
}

/// Refold the merge public input the circuit committed to. It is the four
/// per-slot folds, the output, the private tx hash, and the shared identity, in
/// the order `spp_merge/default.go` chains them.
fn leg_public_input(leg: &MergeChainLeg) -> Result<[u8; 32], ClientError> {
    let private_tx_hash = PrivateTxHash::new(
        &leg.input_utxo_hashes,
        std::slice::from_ref(&leg.output_utxo_hash),
        &leg.external_data_hash,
    )
    .hash()?;
    Ok(create_hash_chain_from_slice(&[
        create_hash_chain_from_slice(&leg.nullifiers)?,
        leg.output_utxo_hash,
        create_hash_chain_from_slice(&leg.utxo_tree_roots)?,
        create_hash_chain_from_slice(&leg.nullifier_tree_roots)?,
        private_tx_hash,
        leg.external_data_hash,
        leg.allow_dummy_inputs,
        leg.signing_pk_field,
    ])?)
}

/// Right-align a field element into the 32-byte big-endian form every hash
/// chain in the protocol folds.
fn field_be(value: &BigUint) -> Result<[u8; 32], ClientError> {
    right_align_slice(&value.to_bytes_be())
}

#[cfg(test)]
mod tests {
    use groth16_solana::groth16::negate_g1_be;

    use super::*;

    fn leg(a: [u8; 64]) -> MergeChainLeg {
        MergeChainLeg {
            proof: Proof {
                a,
                b: [0u8; 128],
                c: [0u8; 64],
                commitment: None,
            },
            nullifiers: [[1u8; 32]; MERGE_INPUT_COUNT],
            utxo_tree_roots: [[2u8; 32]; MERGE_INPUT_COUNT],
            nullifier_tree_roots: [[3u8; 32]; MERGE_INPUT_COUNT],
            input_utxo_hashes: [[4u8; 32]; MERGE_INPUT_COUNT],
            output_utxo_hash: [5u8; 32],
            external_data_hash: [6u8; 32],
            allow_dummy_inputs: [0u8; 32],
            signing_pk_field: [7u8; 32],
        }
    }

    /// The recursive verifier reads A as the prover produced it. Sending the
    /// on-chain form fails inside a pairing with nothing to name the cause.
    #[test]
    fn chained_proof_carries_the_unnegated_a_point() {
        let mut a = [0u8; 64];
        a[31] = 1;
        a[63] = 2;
        let restored = negate_g1_be(&a);

        let json = to_json_merge_chain(&MergeChainInputs {
            levels: vec![1, 1],
            legs: vec![leg(a)],
        });
        assert!(json.contains(&hex64(&restored[32..])), "A was not restored");
    }
}
