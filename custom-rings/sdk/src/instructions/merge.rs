//! Custom-ring binding for SPP's owner-preserving merge.

use solana_address::Address;
use solana_instruction::Instruction;
use thiserror::Error;
use zolana_client::{
    AsyncProverClient, AsyncRpc, ClientError, MergeProofResult, NonInclusionProof, Proof,
    ProofCompressed, ProverClient, Rpc, SpendProof,
};
use zolana_interface::instruction::{instruction_data::merge_ring::MergeRingIxData, MergeRing};
use zolana_keypair::NullifierKey;
use zolana_transaction::{
    error::TransactionError,
    instructions::merge::{MergeProofInputs, MergeTransaction},
    utxo::SppProofInputUtxo,
    ShieldedKeys, SppProofOutputUtxo, WalletUtxo,
};

use crate::{
    instructions::cosigner::{RingPolicy, RingPrefix},
    policy_config_table, tree_id, tree_id_async, AccountReadError, CustomRing, TransferError,
};

pub use zolana_client::MergeProver as MergeRingProver;
pub type MergeRingWitness = MergeRingProver;
pub use zolana_transaction::instructions::merge::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT};

/// A merge plan whose inputs and output are bound to one custom ring.
#[must_use]
#[derive(Clone)]
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
#[derive(Clone)]
pub struct PreparedCustomRingMerge {
    ring: CustomRing,
    inner: MergeProofInputs,
}

#[derive(Debug, Error)]
pub enum MergeError {
    #[error(transparent)]
    AccountRead(#[from] AccountReadError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("custom ring config does not exist")]
    MissingRingConfig,
    #[error("merge inputs belong to another tree")]
    InputTreeMismatch,
    #[error(transparent)]
    Transfer(Box<TransferError>),
}

pub struct CustomRingMergeProofEnvironment<'a, I, R> {
    pub indexer: &'a I,
    pub prover: &'a ProverClient,
    /// Account reads take the Solana RPC, the indexer serves proofs only.
    pub rpc: &'a R,
}

impl From<TransferError> for MergeError {
    fn from(error: TransferError) -> Self {
        Self::Transfer(Box::new(error))
    }
}

pub struct AsyncCustomRingMergeProofEnvironment<'a, I, R> {
    pub indexer: &'a I,
    pub prover: &'a AsyncProverClient,
    pub rpc: &'a R,
}

#[derive(Clone)]
pub struct MergeProofInput {
    pub nullifier_key: NullifierKey,
    pub input_tree: Address,
    pub output_tree: Address,
}

pub struct ProvenCustomRingMerge {
    input_tree: Address,
    output_tree: Address,
    ring: CustomRing,
    cosigner: Option<Address>,
    has_policy: bool,
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
    ) -> MergeRingWitness {
        MergeRingWitness {
            transaction: self.inner,
            nullifier_key,
            proofs,
            dummy_nullifier_proofs,
        }
    }

    pub fn prove<I: Rpc, R: Rpc>(
        mut self,
        input: MergeProofInput,
        env: CustomRingMergeProofEnvironment<'_, I, R>,
    ) -> Result<ProvenCustomRingMerge, MergeError> {
        let has_policy = self
            .ring
            .read_config(env.rpc)?
            .ok_or(MergeError::MissingRingConfig)?
            .has_policy;
        self.validate_source(tree_id(env.rpc, input.input_tree)?)?;
        self.inner.output_tree_id = tree_id(env.rpc, input.output_tree)?;
        if has_policy {
            self.validate_policy(self.ring.read_policy_config(env.rpc)?, &input)?;
        }
        let commitments = self.input_utxo_hashes()?;
        let proofs = fetch_spend_proofs(env.indexer, input.input_tree, &commitments)?;
        let dummy_nullifiers = self.dummy_nullifiers();
        let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
            Vec::new()
        } else {
            env.indexer
                .get_non_inclusion_proofs(input.input_tree, dummy_nullifiers, None)?
                .proofs
        };
        let staged = self.stage(MergeProofs {
            input,
            proofs,
            dummy: dummy_nullifier_proofs,
            has_policy,
        })?;
        let proof = env.prover.prove_merge_ring(&staged.result.inputs)?;
        staged.finish(proof)
    }

    pub async fn prove_async<I: AsyncRpc, R: AsyncRpc>(
        mut self,
        input: MergeProofInput,
        env: AsyncCustomRingMergeProofEnvironment<'_, I, R>,
    ) -> Result<ProvenCustomRingMerge, MergeError> {
        let has_policy = self
            .ring
            .read_config_async(env.rpc)
            .await?
            .ok_or(MergeError::MissingRingConfig)?
            .has_policy;
        self.validate_source(tree_id_async(env.rpc, input.input_tree).await?)?;
        self.inner.output_tree_id = tree_id_async(env.rpc, input.output_tree).await?;
        if has_policy {
            self.validate_policy(self.ring.read_policy_config_async(env.rpc).await?, &input)?;
        }
        let commitments = self.input_utxo_hashes()?;
        let (state, nullifier) = futures::try_join!(
            env.indexer.get_merkle_proofs(
                input.input_tree,
                commitments.iter().map(|entry| entry.utxo_hash).collect(),
                None
            ),
            env.indexer.get_non_inclusion_proofs(
                input.input_tree,
                commitments.iter().map(|entry| entry.nullifier).collect(),
                None
            ),
        )?;
        let proofs = validate_input_proofs(
            input.input_tree,
            &commitments,
            state.proofs,
            nullifier.proofs,
        )?;
        let dummy_nullifiers = self.dummy_nullifiers();
        let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
            Vec::new()
        } else {
            env.indexer
                .get_non_inclusion_proofs(input.input_tree, dummy_nullifiers, None)
                .await?
                .proofs
        };
        let staged = self.stage(MergeProofs {
            input,
            proofs,
            dummy: dummy_nullifier_proofs,
            has_policy,
        })?;
        let proof = env.prover.prove_merge_ring(&staged.result.inputs).await?;
        staged.finish(proof)
    }

    fn validate_source(&self, tree_id: u16) -> Result<(), MergeError> {
        if self
            .inner
            .input_utxos
            .iter()
            .filter(|input| !input.is_dummy())
            .any(|input| input.tree_id != tree_id)
        {
            return Err(MergeError::InputTreeMismatch);
        }
        Ok(())
    }

    fn validate_policy(
        &self,
        policy: Option<custom_ring_interface::PolicyConfig>,
        input: &MergeProofInput,
    ) -> Result<(), MergeError> {
        let policy = policy.ok_or(TransferError::MissingPolicyConfig)?;
        let table = policy_config_table(&policy).map_err(TransferError::from)?;
        if table.window_slots() != 0 && input.output_tree != policy.entries_tree {
            return Err(TransferError::EntriesTreeRequired {
                entries_tree: policy.entries_tree,
            }
            .into());
        }
        Ok(())
    }

    fn stage(self, proofs: MergeProofs) -> Result<StagedMerge, MergeError> {
        let MergeProofs {
            input,
            proofs,
            dummy,
            has_policy,
        } = proofs;
        let ring = self.ring;
        let merged_amount = self.inner.output_utxo.amount;
        let input_count = proofs.len();
        let input_tree = input.input_tree;
        let output_tree = input.output_tree;
        let result = self.witness(input.nullifier_key, proofs, dummy).build()?;
        Ok(StagedMerge {
            ring,
            result,
            input_tree,
            output_tree,
            merged_amount,
            input_count,
            has_policy,
        })
    }
}

struct MergeProofs {
    input: MergeProofInput,
    proofs: Vec<SpendProof>,
    dummy: Vec<NonInclusionProof>,
    has_policy: bool,
}

struct StagedMerge {
    ring: CustomRing,
    result: MergeProofResult,
    input_tree: Address,
    output_tree: Address,
    merged_amount: u64,
    input_count: usize,
    has_policy: bool,
}

impl StagedMerge {
    fn finish(self, proof: Proof) -> Result<ProvenCustomRingMerge, MergeError> {
        let proof = ProofCompressed::try_from(proof)?.to_merge_proof()?;
        Ok(ProvenCustomRingMerge {
            ring: self.ring,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            cosigner: None,
            has_policy: self.has_policy,
            data: self.result.ring_instruction_data(proof),
            output_hash: self.result.output_hash,
            input_count: self.input_count,
            merged_amount: self.merged_amount,
            tx_viewing_pk: self.result.tx_viewing_pk,
            salt: self.result.salt,
            output_data: self.result.output_data.clone(),
        })
    }
}

impl ProvenCustomRingMerge {
    #[must_use = "use the updated merge"]
    pub fn with_cosigner(mut self, cosigner: Address) -> Self {
        self.cosigner = Some(cosigner);
        self
    }

    pub fn instruction(self, payer: Address) -> Instruction {
        CustomRingMergeInstruction {
            ring: self.ring,
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            payer,
            cosigner: self.cosigner,
            has_policy: self.has_policy,
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
    validate_input_proofs(tree, commitments, state_proofs, nullifier_proofs)
}

fn validate_input_proofs(
    tree: Address,
    commitments: &[&SppProofInputUtxo],
    state_proofs: Vec<zolana_client::MerkleProof>,
    nullifier_proofs: Vec<NonInclusionProof>,
) -> Result<Vec<SpendProof>, ClientError> {
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

/// Client instruction for a proved custom-ring merge, the ring's
/// `[cosigner_pda, cosigner]` prefix precedes the forwarded list.
#[must_use]
pub struct CustomRingMergeInstruction {
    pub ring: CustomRing,
    pub input_tree: Address,
    pub output_tree: Address,
    pub payer: Address,
    pub cosigner: Option<Address>,
    /// Mirrors the ring config's policy flag.
    pub has_policy: bool,
    pub data: MergeRingIxData,
}

impl CustomRingMergeInstruction {
    pub fn instruction(self) -> Instruction {
        let Self {
            ring,
            input_tree,
            output_tree,
            payer,
            cosigner,
            has_policy,
            data,
        } = self;
        let mut instruction = MergeRing {
            input_tree,
            output_tree,
            ring_program_id: ring.program_id(),
            payer,
            data: data.merge,
            output_ring_data_hash: data.output_ring_data_hash,
        }
        .instruction();
        let prefix = RingPrefix {
            ring,
            cosigner,
            policy: if has_policy {
                RingPolicy::Config
            } else {
                RingPolicy::Off
            },
        }
        .metas();
        instruction.accounts.splice(0..0, prefix);
        instruction
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
            cosigner: None,
            ring,
            input_tree: Address::new_from_array([1; 32]),
            output_tree: Address::new_from_array([2; 32]),
            payer: Address::new_from_array([3; 32]),
            has_policy: false,
            data,
        }
        .instruction();

        assert_eq!(instruction.program_id, ring.program_id());
        assert_eq!(instruction.accounts[0].pubkey, ring.config_pda());
        assert_eq!(instruction.accounts[1].pubkey, ring.cosigner_pda());
        assert_eq!(
            instruction.accounts[5].pubkey,
            pda::ring_auth(&ring.program_id()).0
        );
        assert!(!instruction.accounts[5].is_signer);
        assert_eq!(
            instruction.data.first(),
            Some(&zolana_interface::instruction::tag::RING_MERGE_TRANSACT)
        );
    }
}
