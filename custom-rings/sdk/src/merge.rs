//! The custom-ring binding of SPP's owner-preserving merge.

use custom_ring_interface::RingMode;
use solana_address::Address;
use solana_instruction::Instruction;
use zolana_client::{
    prover::{
        indexed::{IndexedMergePreparation, ProvenIndexedMerge},
        requests,
    },
    AsyncIndexer, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient, ClientError, MergeProver,
    ProofCompressed,
};
use zolana_interface::instruction::instruction_data::merge_ring::MergeRingIxData;
use zolana_keypair::NullifierKey;
use zolana_program::instruction::MergeRing;
use zolana_transaction::{
    error::TransactionError,
    instructions::merge::{MergeProofInputs, MergeTransaction},
    utxo::SppProofInputUtxo,
    ShieldedKeys, SppProofOutputUtxo, WalletUtxo,
};

pub use zolana_transaction::instructions::merge::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT};

use crate::{transact_ix::ring_prefix, tree_id, CustomRing, RingError};

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

/// A custom-ring merge, compact-padded to its circuit width, ready for tree proofs.
#[must_use]
#[derive(Clone)]
pub struct PreparedCustomRingMerge {
    ring: CustomRing,
    inner: MergeProofInputs,
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

    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        mut self,
        input: MergeProofInput,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenCustomRingMerge, RingError> {
        let config = self
            .ring
            .config(client)
            .await?
            .ok_or(RingError::MissingRingConfig)?;
        // A merge carries no auditor proof, an anonymous ring would hide its balance change.
        if config.mode == RingMode::Anonymous {
            return Err(RingError::AnonymousRingRefused);
        }
        let input_tree_id = tree_id(client, input.input_tree).await?;
        if self
            .inner
            .input_utxos
            .iter()
            .any(|utxo| !utxo.is_dummy() && utxo.tree_id != input_tree_id)
        {
            return Err(RingError::InputTreeMismatch);
        }
        self.inner.output_tree_id = tree_id(client, input.output_tree).await?;
        let data = match client.indexed_prover() {
            Some(prover) => {
                let prepared = IndexedMergePreparation {
                    merge: self.inner.clone(),
                    nullifier_key: input.nullifier_key.clone(),
                }
                .prepare()?;
                match prover.prove_indexed(&prepared).await? {
                    ProvenIndexedMerge::Ring(data) => data,
                    _ => return Err(ClientError::InvalidIndexedRequest.into()),
                }
            }
            None => {
                let commitments = self.inner.input_utxo_hashes()?;
                let witnesses = AsyncWitnessReader::input_witnesses(
                    client.indexer(),
                    &commitments,
                    &self.inner.dummy_nullifiers(),
                    None,
                )
                .await?;
                let result = MergeProver {
                    transaction: self.inner.clone(),
                    nullifier_key: input.nullifier_key.clone(),
                    proofs: witnesses.spend_proofs,
                    dummy_nullifier_proofs: witnesses.dummy_nullifier_proofs,
                    cache: None,
                }
                .build()?;
                let proof = client
                    .prove_request(&requests::merge_ring(&result.inputs)?)
                    .await?;
                result.ring_instruction_data(ProofCompressed::try_from(proof)?.to_merge_proof()?)
            }
        };
        let inner = self.inner;
        Ok(ProvenCustomRingMerge {
            input_tree: input.input_tree,
            output_tree: input.output_tree,
            ring: self.ring,
            cosigner: None,
            data,
            output_hash: inner.output_hash()?,
            input_count: inner
                .input_utxos
                .iter()
                .filter(|utxo| !utxo.is_dummy())
                .count(),
            merged_amount: inner.output_utxo.amount,
            tx_viewing_pk: inner.tx_viewing_pk,
            salt: inner.salt,
            output_data: inner.output_data,
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
            data: self.data,
        }
        .instruction()
    }
}

/// A proven merge, the ring's `[config, cosigner_pda, cosigner]` prefix precedes SPP's list.
#[must_use]
pub struct CustomRingMergeInstruction {
    pub ring: CustomRing,
    pub input_tree: Address,
    pub output_tree: Address,
    pub payer: Address,
    pub cosigner: Option<Address>,
    pub data: MergeRingIxData,
}

impl CustomRingMergeInstruction {
    pub fn instruction(self) -> Instruction {
        let mut instruction = MergeRing {
            input_tree: self.input_tree,
            output_tree: self.output_tree,
            ring_program_id: self.ring.program_id(),
            payer: self.payer,
            data: self.data.merge,
            output_ring_data_hash: self.data.output_ring_data_hash,
            cache: None,
        }
        .instruction();
        instruction
            .accounts
            .splice(0..0, ring_prefix(self.ring, self.cosigner));
        instruction
    }
}
