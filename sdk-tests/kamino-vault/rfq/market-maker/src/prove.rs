use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use solana_address::Address;
use solana_instruction::Instruction;
use tokio::sync::{Semaphore, SemaphorePermit};
use zolana_client::{
    assemble, verify_confidential_transfer_inputs, AsyncProverClient, AsyncRpc, AsyncWitnessReader,
    AsyncZolanaIndexer, ClientError, InputWitnesses, ProofAuthority, ProofCompressed,
};
use zolana_interface::pda;
use zolana_keypair::ShieldedKeypair;
use zolana_program::instruction::Transact;
use zolana_transaction::utxo::SppProofInputUtxo;

use super::{error::MakerError, step::ProofWork};

pub struct ProofQueueConfig {
    pub authority: Arc<ShieldedKeypair>,
    pub indexer: Arc<AsyncZolanaIndexer>,
    pub prover: Arc<AsyncProverClient>,
    pub base_workers: usize,
    pub max_workers: usize,
    pub payer: Address,
}

pub struct ProofQueue {
    authority: Arc<ShieldedKeypair>,
    indexer: Arc<AsyncZolanaIndexer>,
    prover: Arc<AsyncProverClient>,
    workers: Semaphore,
    worker_count: AtomicUsize,
    max_workers: usize,
    payer: Address,
}

impl ProofQueue {
    pub fn new(config: ProofQueueConfig) -> Self {
        let base = config.base_workers.max(1);
        Self {
            authority: config.authority,
            indexer: config.indexer,
            prover: config.prover,
            workers: Semaphore::new(base),
            worker_count: AtomicUsize::new(base),
            max_workers: config.max_workers.max(base),
            payer: config.payer,
        }
    }

    pub async fn prove(&self, work: ProofWork) -> Result<Instruction, MakerError> {
        let _worker = self.acquire_worker().await?;
        self.prove_transfer(work).await
    }

    async fn acquire_worker(&self) -> Result<SemaphorePermit<'_>, MakerError> {
        if self.workers.available_permits() == 0 {
            let current = self.worker_count.load(Ordering::Relaxed);
            let grown = current < self.max_workers
                && self
                    .worker_count
                    .compare_exchange(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok();
            if grown {
                self.workers.add_permits(1);
            }
        }
        self.workers
            .acquire()
            .await
            .map_err(|_| MakerError::CoordinatorStopped)
    }

    async fn witnesses(
        &self,
        tree_id: u16,
        commitments: &[&SppProofInputUtxo],
        dummy_nullifiers: Vec<[u8; 32]>,
    ) -> Result<InputWitnesses, MakerError> {
        if commitments.is_empty() {
            let dummy_nullifier_proofs = self
                .indexer
                .get_non_inclusion_proofs(pda::tree(tree_id), dummy_nullifiers, None)
                .await
                .map_err(MakerError::Indexer)?
                .proofs;
            return Ok(InputWitnesses {
                spend_proofs: Vec::new(),
                dummy_nullifier_proofs,
            });
        }
        AsyncWitnessReader::input_witnesses(
            self.indexer.as_ref(),
            commitments,
            &dummy_nullifiers,
            None,
        )
        .await
        .map_err(MakerError::Indexer)
    }

    async fn prove_transfer(&self, work: ProofWork) -> Result<Instruction, MakerError> {
        let ProofWork {
            inputs: proof_inputs,
            interface_accounts,
        } = work;
        let tree_id = proof_inputs
            .input_utxos
            .first()
            .map(|input| input.tree_id)
            .ok_or(ClientError::NoInputs)?;
        let witnesses = self
            .witnesses(
                tree_id,
                &proof_inputs.input_utxo_hashes()?,
                proof_inputs.dummy_nullifiers(),
            )
            .await?;
        let owner_signers = proof_inputs.owner_signer_pubkeys()?;
        let output_tree = pda::tree(proof_inputs.output_tree_id);
        let mut assembled = assemble(
            proof_inputs,
            &witnesses.spend_proofs,
            &witnesses.dummy_nullifier_proofs,
        )?;
        self.authority
            .complete_inputs(&mut assembled.prover_inputs.inputs)?;
        let inputs = &assembled.prover_inputs;
        let proof = self
            .prover
            .prove_transfer(inputs)
            .await
            .map_err(MakerError::Prover)?;
        verify_confidential_transfer_inputs(inputs, assembled.public_input_hash, &proof)?;
        let input_trees = assembled
            .input_tree_ids
            .iter()
            .copied()
            .map(pda::tree)
            .collect();
        Ok(Transact {
            payer: self.payer,
            input_trees,
            output_tree,
            owner_signers,
            interface_transfer_accounts: interface_accounts,
            data: assembled.with_proof(ProofCompressed::try_from(proof)?.to_transact_proof()),
        }
        .instruction())
    }
}
