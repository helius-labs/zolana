//! Custom-ring binding for SPP's owner-preserving merge.

use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    ClientError, NonInclusionProof, ProofCompressed, ProverClient, Rpc, SpendProof,
};
use zolana_interface::instruction::{instruction_data::merge_ring::MergeRingIxData, MergeRing};
use zolana_keypair::{NullifierKey, ShieldedKeypairTrait};
use zolana_transaction::{
    error::TransactionError,
    instructions::{
        merge_ring::{MergeRing as MergePlan, PreparedMergeRing},
        types::{InputUtxoContext, SppProofInputUtxo},
    },
    SppProofOutputUtxo,
};

use crate::CustomRing;

pub use zolana_client::{
    MergeRingProver as CustomRingMergeProver, MergeRingWitness as CustomRingMergeWitness,
};
pub use zolana_transaction::instructions::merge::MERGE_INPUTS;

/// A merge plan whose inputs and output are bound to one custom ring.
#[must_use]
pub struct CustomRingMerge {
    ring: CustomRing,
    inner: MergePlan,
}

impl CustomRingMerge {
    pub fn new<K: ShieldedKeypairTrait>(
        ring: CustomRing,
        keypair: &K,
        inputs: Vec<SppProofInputUtxo>,
        output_ring_data_hash: Option<[u8; 32]>,
    ) -> Result<Self, TransactionError> {
        let inner = MergePlan::new(keypair, inputs, ring.program_id(), output_ring_data_hash)?;
        Ok(Self { ring, inner })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.inner = self.inner.with_expiry(expiry_unix_ts);
        self
    }

    pub fn prepare(self) -> PreparedCustomRingMerge {
        PreparedCustomRingMerge {
            ring: self.ring,
            inner: self.inner.prepare(),
        }
    }
}

/// An 8-slot custom-ring merge ready for tree proofs.
#[must_use]
pub struct PreparedCustomRingMerge {
    ring: CustomRing,
    inner: PreparedMergeRing,
}

pub struct CustomRingMergeProofEnvironment<'a, I> {
    pub indexer: &'a I,
    pub prover: &'a ProverClient,
}

pub struct ProvenCustomRingMerge {
    ring: CustomRing,
    pub data: MergeRingIxData,
    pub output_hash: [u8; 32],
    pub input_count: usize,
    pub merged_amount: u64,
}

impl PreparedCustomRingMerge {
    pub const fn ring(&self) -> CustomRing {
        self.ring
    }

    pub fn inputs(&self) -> &[SppProofInputUtxo] {
        &self.inner.inputs
    }

    pub const fn output(&self) -> &SppProofOutputUtxo {
        &self.inner.output
    }

    pub fn input_utxo_hashes(&self) -> Result<Vec<InputUtxoContext>, TransactionError> {
        self.inner.input_utxo_hashes()
    }

    pub fn dummy_nullifiers(
        &self,
        nullifier_key: &NullifierKey,
    ) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.inner.dummy_nullifiers(nullifier_key)
    }

    pub fn witness(
        self,
        nullifier_key: NullifierKey,
        proofs: Vec<SpendProof>,
        dummy_nullifier_proofs: Vec<NonInclusionProof>,
    ) -> CustomRingMergeWitness {
        CustomRingMergeWitness {
            prepared: self.inner,
            nullifier_key,
            proofs,
            dummy_nullifier_proofs,
        }
    }

    pub fn prove<I: Rpc>(
        self,
        nullifier_key: NullifierKey,
        input_tree: Address,
        env: CustomRingMergeProofEnvironment<'_, I>,
    ) -> Result<ProvenCustomRingMerge, ClientError> {
        let ring = self.ring;
        let output_ring_data_hash = self.inner.output.ring_data_hash.unwrap_or_default();
        let merged_amount = self.inner.output.amount;
        let commitments = self.input_utxo_hashes()?;
        let input_count = commitments.len();
        let proofs = fetch_spend_proofs(env.indexer, input_tree, &commitments)?;
        let dummy_nullifiers = self.dummy_nullifiers(&nullifier_key)?;
        let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
            Vec::new()
        } else {
            env.indexer
                .get_non_inclusion_proofs(input_tree, dummy_nullifiers, None)?
                .proofs
        };
        let result = CustomRingMergeProver::try_from(self.witness(
            nullifier_key,
            proofs,
            dummy_nullifier_proofs,
        ))?
        .build()?;
        let proof = env.prover.prove_merge_ring(&result.inputs)?;
        let proof = ProofCompressed::try_from(proof)?.to_merge_proof()?;

        Ok(ProvenCustomRingMerge {
            ring,
            data: result.ring_instruction_data(proof, output_ring_data_hash),
            output_hash: result.output_hash,
            input_count,
            merged_amount,
        })
    }
}

impl ProvenCustomRingMerge {
    pub fn instruction(
        self,
        input_tree: Address,
        output_tree: Address,
        payer: Address,
    ) -> Instruction {
        CustomRingMergeInstruction {
            ring: self.ring,
            input_tree,
            output_tree,
            payer,
            data: self.data,
        }
        .instruction()
    }
}

fn fetch_spend_proofs<I: Rpc>(
    indexer: &I,
    tree: Address,
    commitments: &[InputUtxoContext],
) -> Result<Vec<SpendProof>, ClientError> {
    let state_proofs = indexer
        .get_merkle_proofs(
            tree,
            commitments.iter().map(|entry| entry.utxo_hash).collect(),
            None,
        )?
        .proofs;
    let nullifier_proofs = indexer
        .get_non_inclusion_proofs(
            tree,
            commitments.iter().map(|entry| entry.nullifier).collect(),
            None,
        )?
        .proofs;
    if state_proofs.len() != commitments.len() || nullifier_proofs.len() != commitments.len() {
        return Err(ClientError::IncompleteInputProofs {
            expected: commitments.len(),
            state: state_proofs.len(),
            nullifier: nullifier_proofs.len(),
        });
    }
    state_proofs
        .into_iter()
        .zip(nullifier_proofs)
        .zip(commitments)
        .enumerate()
        .map(|(index, ((state, nullifier), commitment))| {
            if state.leaf != commitment.utxo_hash {
                return Err(ClientError::StateProofLeafMismatch { index });
            }
            if state.merkle_context.tree != tree {
                return Err(ClientError::StateProofTreeMismatch { index });
            }
            if nullifier.leaf != commitment.nullifier {
                return Err(ClientError::NullifierProofLeafMismatch { index });
            }
            if nullifier.merkle_context.tree != tree {
                return Err(ClientError::NullifierProofTreeMismatch { index });
            }
            Ok(SpendProof { state, nullifier })
        })
        .collect()
}

/// Client instruction for a proved custom-ring merge.
#[must_use]
pub struct CustomRingMergeInstruction {
    pub ring: CustomRing,
    pub input_tree: Address,
    pub output_tree: Address,
    pub payer: Address,
    pub data: MergeRingIxData,
}

impl CustomRingMergeInstruction {
    pub fn instruction(self) -> Instruction {
        let Self {
            ring,
            input_tree,
            output_tree,
            payer,
            data,
        } = self;
        MergeRing {
            input_tree,
            output_tree,
            ring_program_id: ring.program_id(),
            payer,
            data: data.merge,
            output_ring_data_hash: data.output_ring_data_hash,
        }
        .instruction()
    }
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use zolana_interface::{instruction::instruction_data::merge_transact::MergeProof, pda};
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{instructions::types::SppProofInputUtxo, Utxo, SOL_MINT};

    use super::*;

    #[test]
    fn merge_keeps_owner_asset_amount_and_ring() {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        let ring = CustomRing::new(Address::new_from_array([9; 32]));
        let inputs = [3, 5].map(|amount| {
            SppProofInputUtxo::new(
                Utxo {
                    owner: owner.signing_pubkey(),
                    asset: SOL_MINT,
                    amount,
                    blinding: [amount as u8; 32],
                    ring_program_id: Some(ring.program_id()),
                    data: Default::default(),
                },
                &owner,
            )
        });

        let prepared = CustomRingMerge::new(ring, &owner, inputs.into(), None)
            .expect("merge")
            .prepare();

        assert_eq!(prepared.inputs().len(), MERGE_INPUTS);
        assert_eq!(prepared.output().amount, 8);
        assert_eq!(prepared.output().ring_program_id, Some(ring.program_id()));
        assert_eq!(prepared.output().asset, SOL_MINT);
    }

    #[test]
    fn instruction_targets_the_same_ring_and_uses_its_authority() {
        let ring = CustomRing::new(Address::new_from_array([9; 32]));
        let data = MergeRingIxData {
            output_ring_data_hash: [7; 32],
            merge: zolana_interface::instruction::MergeTransactIxData {
                expiry_unix_ts: u64::MAX,
                proof: MergeProof::zeroed(),
                output_utxo_hash: [0; 32],
                nullifiers: vec![[0; 32]; MERGE_INPUTS],
                utxo_tree_root_index: vec![0; MERGE_INPUTS],
                nullifier_tree_root_index: vec![0; MERGE_INPUTS],
                private_tx_hash: [0; 32],
                eddsa_owner: false,
            },
        };
        let instruction = CustomRingMergeInstruction {
            ring,
            input_tree: Address::new_from_array([1; 32]),
            output_tree: Address::new_from_array([2; 32]),
            payer: Address::new_from_array([3; 32]),
            data,
        }
        .instruction();

        assert_eq!(instruction.program_id, ring.program_id());
        assert_eq!(
            instruction.accounts[2].pubkey,
            pda::ring_auth(&ring.program_id()).0
        );
        assert!(!instruction.accounts[2].is_signer);
        assert_eq!(
            instruction.data.first(),
            Some(&zolana_interface::instruction::tag::RING_MERGE_TRANSACT)
        );
    }
}
