//! Custom-ring binding for SPP's owner-preserving merge.

use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    ClientError, NonInclusionProof, ProofCompressed, ProverClient, Rpc, SpendProof,
};
use zolana_interface::instruction::{instruction_data::merge_ring::MergeRingIxData, MergeRing};
use zolana_keypair::NullifierKey;
use zolana_transaction::{
    error::TransactionError,
    instructions::merge::{MergeProofInputs, MergeTransaction},
    utxo::SppProofInputUtxo,
    ShieldedKeys, SppProofOutputUtxo, WalletUtxo,
};

use crate::CustomRing;

use zolana_client::MergeProver;
pub use zolana_transaction::instructions::merge::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT};

/// A merge plan whose inputs and output are bound to one custom ring.
#[must_use]
pub struct CustomRingMerge {
    ring: CustomRing,
    inner: MergeTransaction,
}

impl CustomRingMerge {
    pub fn new(
        ring: CustomRing,
        inputs: Vec<WalletUtxo>,
        output_ring_data_hash: Option<[u8; 32]>,
    ) -> Result<Self, TransactionError> {
        let inner =
            MergeTransaction::new_with_ring(inputs, ring.program_id(), output_ring_data_hash)?;
        Ok(Self { ring, inner })
    }

    pub fn with_expiry(mut self, expiry_unix_ts: u64) -> Self {
        self.inner = self.inner.with_expiry(expiry_unix_ts);
        self
    }

    pub fn with_output_tree_id(mut self, tree_id: u16) -> Self {
        self.inner = self.inner.with_output_tree_id(tree_id);
        self
    }

    pub fn encrypt<K: ShieldedKeys + ?Sized>(
        self,
        keys: &K,
    ) -> Result<PreparedCustomRingMerge, TransactionError> {
        Ok(PreparedCustomRingMerge {
            ring: self.ring,
            inner: self.inner.encrypt(keys)?,
        })
    }
}

/// An 8-slot custom-ring merge ready for tree proofs.
#[must_use]
pub struct PreparedCustomRingMerge {
    ring: CustomRing,
    inner: MergeProofInputs,
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
    pub tx_viewing_pk: [u8; 33],
    pub salt: [u8; 16],
    pub output_data: zolana_event::MessageData,
}

impl PreparedCustomRingMerge {
    pub const fn ring(&self) -> CustomRing {
        self.ring
    }

    pub fn inputs(&self) -> &[SppProofInputUtxo] {
        &self.inner.input_utxos
    }

    pub const fn output(&self) -> &SppProofOutputUtxo {
        &self.inner.output_utxo
    }

    pub fn input_utxo_hashes(&self) -> Result<Vec<&SppProofInputUtxo>, TransactionError> {
        self.inner.input_utxo_hashes()
    }

    pub fn dummy_nullifiers(&self) -> Vec<[u8; 32]> {
        self.inner.dummy_nullifiers()
    }

    pub fn witness(
        self,
        nullifier_key: NullifierKey,
        proofs: Vec<SpendProof>,
        dummy_nullifier_proofs: Vec<NonInclusionProof>,
    ) -> MergeProver {
        MergeProver {
            transaction: self.inner,
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
        let merged_amount = self.inner.output_utxo.amount;
        let commitments = self.input_utxo_hashes()?;
        let input_count = commitments.len();
        let proofs = fetch_spend_proofs(env.indexer, input_tree, &commitments)?;
        let dummy_nullifiers = self.dummy_nullifiers();
        let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
            Vec::new()
        } else {
            env.indexer
                .get_non_inclusion_proofs(input_tree, dummy_nullifiers, None)?
                .proofs
        };
        let result = self
            .witness(nullifier_key, proofs, dummy_nullifier_proofs)
            .build()?;
        let proof = env.prover.prove_merge_ring(&result.inputs)?;
        let proof = ProofCompressed::try_from(proof)?.to_merge_proof()?;

        Ok(ProvenCustomRingMerge {
            ring,
            data: result.ring_instruction_data(proof),
            output_hash: result.output_hash,
            input_count,
            merged_amount,
            tx_viewing_pk: result.tx_viewing_pk,
            salt: result.salt,
            output_data: result.output_data,
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
    commitments: &[&SppProofInputUtxo],
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
    use zolana_transaction::{Mint, Utxo};

    use super::*;

    #[test]
    fn merge_keeps_owner_asset_amount_and_ring() {
        let owner = ShieldedKeypair::new_ed25519().expect("owner");
        let ring = CustomRing::new(Address::new_from_array([9; 32]));
        let inputs = [3, 5].map(|amount| {
            zolana_test_utils::utxo::wallet(
                Utxo {
                    owner: owner.signing_pubkey(),
                    asset: Mint::SOL,
                    amount,
                    blinding: [amount as u8; 32],
                    ring_program_id: Some(ring.program_id()),
                    data: Default::default(),
                },
                &owner.nullifier_key,
                0,
                amount,
                None,
                None,
            )
            .expect("input_utxo")
        });

        let prepared = CustomRingMerge::new(ring, inputs.into(), None)
            .expect("merge")
            .encrypt(&owner)
            .expect("prepare");

        assert_eq!(prepared.inputs().len(), MERGE_DEFAULT_INPUT_COUNT);
        assert_eq!(prepared.output().amount, 8);
        assert_eq!(prepared.output().ring_program_id, Some(ring.program_id()));
        assert_eq!(prepared.output().asset, Mint::SOL);
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
                nullifiers: vec![[0; 32]; MERGE_DEFAULT_INPUT_COUNT],
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
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
