//! High-level Zolana client.
//!
//! [`ZolanaClient`] owns Solana RPC, Photon, and the prover. After
//! [`sign_private_transaction`] returns a signed native Solana transaction.
//! Submit it through the client's RPC adapter, then confirm on-chain and wait
//! for Photon indexing with [`ZolanaClient::confirm_private_transaction`].

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Slot;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction as SolanaTransaction};
use solana_transaction_status_client_types::TransactionStatus;
use zolana_interface::instruction::Transact;
use zolana_keypair::hash::sha256_be;
use zolana_transaction::instructions::{transact::SignedTransaction, types::InputCommitment};

use crate::{
    actions::SignedPrivateTransaction,
    error::ClientError,
    indexer::{AsyncZolanaIndexer, ZolanaIndexer},
    prover::{
        transact::witness::{assemble, ProverInputs, SpendProof},
        AsyncProverClient, ProofCompressed, ProverClient,
    },
    rpc::{
        AsyncRpc, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse, ProveResult, Rpc,
        ShieldedTransactionStream,
    },
};

/// Compute-unit ceiling a private transaction is submitted with unless the
/// caller overrides it. A shielded `Transact` verifies a Groth16 proof on-chain,
/// which does not fit inside the default per-instruction budget.
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 1_400_000;

#[derive(Clone, Copy, Debug)]
pub struct IndexerPollConfig {
    pub poll_interval: Duration,
    pub timeout: Duration,
}

impl Default for IndexerPollConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(500),
            timeout: Duration::from_secs(120),
        }
    }
}

/// Unified client for private transaction proving and submission helpers.
///
/// The caller should not have to thread Solana RPC, Photon, and prover handles
/// through each step. This client owns those services. Proving and native Solana
/// transaction construction happen during [`sign_private_transaction`]; submission
/// is the caller's RPC adapter.
pub struct ZolanaClient<R> {
    rpc: R,
    indexer: ZolanaIndexer,
    prover: ProverClient,
    async_indexer: AsyncZolanaIndexer,
    async_prover: AsyncProverClient,
    tree: Address,
    cu_limit: u32,
    cu_price_micro_lamports: Option<u64>,
    indexer_poll: IndexerPollConfig,
    send_config: Option<RpcSendTransactionConfig>,
}

impl<R> ZolanaClient<R> {
    pub fn new(
        rpc: R,
        indexer: ZolanaIndexer,
        prover: ProverClient,
        async_indexer: AsyncZolanaIndexer,
        async_prover: AsyncProverClient,
        tree: Address,
    ) -> Self {
        Self {
            rpc,
            indexer,
            prover,
            async_indexer,
            async_prover,
            tree,
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            cu_price_micro_lamports: None,
            indexer_poll: IndexerPollConfig::default(),
            send_config: None,
        }
    }

    pub fn from_urls(
        rpc: R,
        indexer_url: impl AsRef<str>,
        prover_url: impl Into<String>,
        tree: Address,
    ) -> Self {
        let indexer_url = indexer_url.as_ref().to_string();
        let prover_url = prover_url.into();
        Self::new(
            rpc,
            ZolanaIndexer::new(&indexer_url),
            ProverClient::new(prover_url.clone()),
            AsyncZolanaIndexer::new(indexer_url),
            AsyncProverClient::new(prover_url),
            tree,
        )
    }

    pub fn with_compute_unit_limit(mut self, cu_limit: u32) -> Self {
        self.cu_limit = cu_limit;
        self
    }

    pub fn with_compute_unit_price(mut self, micro_lamports: u64) -> Self {
        self.cu_price_micro_lamports = Some(micro_lamports);
        self
    }

    pub fn with_indexer_poll_config(mut self, config: IndexerPollConfig) -> Self {
        self.indexer_poll = config;
        self
    }

    pub fn with_send_transaction_config(mut self, config: RpcSendTransactionConfig) -> Self {
        self.send_config = Some(config);
        self
    }

    pub fn tree(&self) -> Address {
        self.tree
    }

    pub fn rpc(&self) -> &R {
        &self.rpc
    }
}

impl<R: Rpc> ZolanaClient<R> {
    pub(crate) fn finish_submission_sync(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: &dyn Signer,
        recent_blockhash: Hash,
    ) -> Result<SolanaTransaction, ClientError> {
        self.finish_submission_sync_with(signed, fee_payer, recent_blockhash, |inputs| {
            let proof = match inputs {
                ProverInputs::P256(inputs) => self.prover.prove_transfer_p256(inputs)?,
                ProverInputs::Eddsa(inputs) => self.prover.prove_transfer(inputs)?,
            };
            ProofCompressed::try_from(proof)
        })
    }

    pub(crate) fn finish_submission_sync_with(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: &dyn Signer,
        recent_blockhash: Hash,
        prove: impl FnOnce(&ProverInputs) -> Result<ProofCompressed, ClientError>,
    ) -> Result<SolanaTransaction, ClientError> {
        validate_fee_payer(&signed.transaction.payer_pubkey_hash, fee_payer)?;
        validate_transaction_tree(signed.tree, self.tree)?;
        let commitments = signed.transaction.input_commitments()?;
        let spend_proofs = fetch_spend_proofs(&self.indexer, self.tree, &commitments)?;
        let assembled = assemble(signed.transaction.clone(), &spend_proofs)?;
        let proof = prove(&assembled.prover_inputs)?.to_transact_proof();
        build_signed_solana_transaction(
            self.cu_limit,
            self.cu_price_micro_lamports,
            fee_payer,
            signed.tree,
            signed.withdrawal,
            assembled.with_proof(proof),
            recent_blockhash,
        )
    }

    /// Wait until the transaction is confirmed on-chain and Photon has indexed it.
    pub fn confirm_private_transaction_sync(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        wait_for_rpc_confirmation(self.rpc(), signature, self.indexer_poll)?;
        let tags = self
            .rpc()
            .transact_output_view_tags_from_signature(signature)?;
        wait_for_indexed_transaction(&self.indexer, &tags, signature, self.indexer_poll)
    }
}

impl<R: AsyncRpc> ZolanaClient<R> {
    pub(crate) async fn finish_submission(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: &dyn Signer,
        recent_blockhash: Hash,
    ) -> Result<SolanaTransaction, ClientError> {
        validate_fee_payer(&signed.transaction.payer_pubkey_hash, fee_payer)?;
        validate_transaction_tree(signed.tree, self.tree)?;
        let commitments = signed.transaction.input_commitments()?;
        let spend_proofs =
            fetch_spend_proofs_async(&self.async_indexer, self.tree, &commitments).await?;
        let assembled = assemble(signed.transaction.clone(), &spend_proofs)?;
        let proof = match &assembled.prover_inputs {
            ProverInputs::P256(inputs) => self.async_prover.prove_transfer_p256(inputs).await?,
            ProverInputs::Eddsa(inputs) => self.async_prover.prove_transfer(inputs).await?,
        };
        let proof = ProofCompressed::try_from(proof)?.to_transact_proof();
        build_signed_solana_transaction(
            self.cu_limit,
            self.cu_price_micro_lamports,
            fee_payer,
            signed.tree,
            signed.withdrawal,
            assembled.with_proof(proof),
            recent_blockhash,
        )
    }

    /// Wait until the transaction is confirmed on-chain and Photon has indexed it.
    pub async fn confirm_private_transaction(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        wait_for_rpc_confirmation_async(self.rpc(), signature, self.indexer_poll).await?;
        let tags = self
            .rpc()
            .transact_output_view_tags_from_signature(signature)
            .await?;
        wait_for_indexed_transaction_async(&self.async_indexer, &tags, signature, self.indexer_poll)
            .await
    }
}

#[async_trait(?Send)]
impl<R: AsyncRpc> AsyncRpc for ZolanaClient<R> {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.rpc.get_account(address).await
    }

    async fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        self.rpc.get_multiple_accounts(addresses).await
    }

    async fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        self.rpc.get_program_accounts(program_id).await
    }

    async fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        self.rpc.get_balance(address).await
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.rpc.get_latest_blockhash().await
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        self.rpc.get_block_height().await
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        self.rpc.get_slot().await
    }

    async fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        self.rpc.get_transaction_slot(signature).await
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.rpc.get_signature_statuses(signatures).await
    }

    async fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
    ) -> Result<u64, ClientError> {
        self.rpc
            .get_minimum_balance_for_rent_exemption(data_len)
            .await
    }

    async fn health(&self) -> Result<(), ClientError> {
        self.rpc.health().await
    }

    async fn send_transaction(
        &self,
        transaction: &SolanaTransaction,
    ) -> Result<Signature, ClientError> {
        self.rpc.send_transaction(transaction).await
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &SolanaTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.rpc
            .send_transaction_with_config(transaction, config)
            .await
    }

    async fn send_versioned_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.rpc
            .send_versioned_transaction_with_config(transaction, config)
            .await
    }

    async fn process_transaction(
        &self,
        transaction: SolanaTransaction,
    ) -> Result<Signature, ClientError> {
        self.rpc.process_transaction(transaction).await
    }

    async fn process_transaction_with_context(
        &self,
        transaction: SolanaTransaction,
    ) -> Result<(Signature, Slot), ClientError> {
        self.rpc.process_transaction_with_context(transaction).await
    }

    async fn process_versioned_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.rpc.process_versioned_transaction(transaction).await
    }

    async fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.rpc.confirm_transaction(signature).await
    }

    async fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        self.rpc
            .transact_output_view_tags_from_signature(signature)
            .await
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        self.rpc.should_retry(error) || self.async_indexer.should_retry(error)
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.async_indexer
            .get_encrypted_utxos_by_tags(tags, cursor, limit)
            .await
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.async_indexer
            .get_shielded_transactions_by_tags(tags, cursor, limit)
            .await
    }

    async fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        self.async_indexer
            .subscribe_to_shielded_transactions_by_tags(tags)
            .await
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.async_indexer
            .get_merkle_proofs(tree_account, leaves)
            .await
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.async_indexer
            .get_non_inclusion_proofs(tree_account, leaves)
            .await
    }

    async fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputCommitment],
    ) -> Result<Vec<SpendProof>, ClientError> {
        fetch_spend_proofs_async(&self.async_indexer, self.tree, input_utxo_commitments).await
    }

    async fn prove(&self, transaction: SignedTransaction) -> Result<ProveResult, ClientError> {
        let commitments = transaction.input_commitments()?;
        let input_merkle_proofs = self.get_input_merkle_proofs(&commitments).await?;
        let assembled = assemble(transaction, &input_merkle_proofs)?;
        let (proof, circuit_id) = match &assembled.prover_inputs {
            ProverInputs::P256(inputs) => (self.async_prover.prove_transfer_p256(inputs).await?, 1),
            ProverInputs::Eddsa(inputs) => (self.async_prover.prove_transfer(inputs).await?, 0),
        };
        Ok(ProveResult {
            proof: ProofCompressed::try_from(proof)?,
            public_inputs: vec![assembled.public_input_hash],
            circuit_id,
        })
    }
}

impl<R: Rpc> Rpc for ZolanaClient<R> {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.rpc.get_account(address)
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        self.rpc.get_multiple_accounts(addresses)
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        self.rpc.get_program_accounts(program_id)
    }

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        self.rpc.get_balance(address)
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.rpc.get_latest_blockhash()
    }

    fn get_block_height(&self) -> Result<u64, ClientError> {
        self.rpc.get_block_height()
    }

    fn get_slot(&self) -> Result<u64, ClientError> {
        self.rpc.get_slot()
    }

    fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        self.rpc.get_transaction_slot(signature)
    }

    fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.rpc.get_signature_statuses(signatures)
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        self.rpc.get_minimum_balance_for_rent_exemption(data_len)
    }

    fn health(&self) -> Result<(), ClientError> {
        self.rpc.health()
    }

    fn send_transaction(&self, transaction: &SolanaTransaction) -> Result<Signature, ClientError> {
        self.rpc.send_transaction(transaction)
    }

    fn send_transaction_with_config(
        &self,
        transaction: &SolanaTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.rpc.send_transaction_with_config(transaction, config)
    }

    fn send_versioned_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.rpc
            .send_versioned_transaction_with_config(transaction, config)
    }

    fn process_transaction(
        &self,
        transaction: SolanaTransaction,
    ) -> Result<Signature, ClientError> {
        self.rpc.process_transaction(transaction)
    }

    fn process_transaction_with_context(
        &self,
        transaction: SolanaTransaction,
    ) -> Result<(Signature, Slot), ClientError> {
        self.rpc.process_transaction_with_context(transaction)
    }

    fn process_versioned_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.rpc.process_versioned_transaction(transaction)
    }

    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.rpc.confirm_transaction(signature)
    }

    fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        self.rpc.transact_output_view_tags_from_signature(signature)
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        self.rpc.should_retry(error) || self.indexer.should_retry(error)
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.indexer
            .get_encrypted_utxos_by_tags(tags, cursor, limit)
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.indexer
            .get_shielded_transactions_by_tags(tags, cursor, limit)
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        self.indexer
            .subscribe_to_shielded_transactions_by_tags(tags)
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.indexer.get_merkle_proofs(tree_account, leaves)
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.indexer.get_non_inclusion_proofs(tree_account, leaves)
    }

    fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputCommitment],
    ) -> Result<Vec<SpendProof>, ClientError> {
        fetch_spend_proofs(&self.indexer, self.tree, input_utxo_commitments)
    }

    fn prove(&self, transaction: SignedTransaction) -> Result<ProveResult, ClientError> {
        let commitments = transaction.input_commitments()?;
        let input_merkle_proofs = self.get_input_merkle_proofs(&commitments)?;
        let assembled = assemble(transaction, &input_merkle_proofs)?;
        let (proof, circuit_id) = match &assembled.prover_inputs {
            ProverInputs::P256(inputs) => (self.prover.prove_transfer_p256(inputs)?, 1),
            ProverInputs::Eddsa(inputs) => (self.prover.prove_transfer(inputs)?, 0),
        };
        Ok(ProveResult {
            proof: ProofCompressed::try_from(proof)?,
            public_inputs: vec![assembled.public_input_hash],
            circuit_id,
        })
    }
}

fn build_signed_solana_transaction(
    cu_limit: u32,
    cu_price_micro_lamports: Option<u64>,
    fee_payer: &dyn Signer,
    tree: Address,
    withdrawal: Option<zolana_interface::instruction::TransactWithdrawal>,
    transact_data: zolana_interface::instruction::instruction_data::transact::TransactIxData,
    recent_blockhash: Hash,
) -> Result<SolanaTransaction, ClientError> {
    let transact_ix = Transact {
        payer: fee_payer.pubkey(),
        tree: Pubkey::new_from_array(tree.to_bytes()),
        withdrawal,
        data: transact_data,
    }
    .instruction();
    let instructions = submit_instructions(cu_limit, cu_price_micro_lamports, transact_ix);
    let payer = fee_payer.pubkey();
    let message = Message::new(&instructions, Some(&payer));
    Ok(SolanaTransaction::new(
        &[fee_payer],
        message,
        recent_blockhash,
    ))
}

fn validate_fee_payer(
    expected_payer_hash: &[u8; 32],
    fee_payer: &dyn Signer,
) -> Result<(), ClientError> {
    let actual_payer_hash = sha256_be(&fee_payer.pubkey().to_bytes());
    if *expected_payer_hash != actual_payer_hash {
        return Err(ClientError::FeePayerMismatch);
    }
    Ok(())
}

fn validate_transaction_tree(
    transaction_tree: Address,
    client_tree: Address,
) -> Result<(), ClientError> {
    if transaction_tree != client_tree {
        return Err(ClientError::TreeMismatch {
            transaction_tree: transaction_tree.to_bytes(),
            client_tree: client_tree.to_bytes(),
        });
    }
    Ok(())
}

fn submit_instructions(
    cu_limit: u32,
    cu_price_micro_lamports: Option<u64>,
    transact: Instruction,
) -> Vec<Instruction> {
    let mut instructions = Vec::with_capacity(2 + usize::from(cu_price_micro_lamports.is_some()));
    instructions.push(ComputeBudgetInstruction::set_compute_unit_limit(cu_limit));
    if let Some(price) = cu_price_micro_lamports {
        instructions.push(ComputeBudgetInstruction::set_compute_unit_price(price));
    }
    instructions.push(transact);
    instructions
}

/// Resolve the spend proof (state inclusion + nullifier non-inclusion) for each
/// input commitment on `tree`, in commitment order. Batches both indexer lookups
/// so a multi-input spend costs two round trips, not two per input.
fn fetch_spend_proofs(
    indexer: &ZolanaIndexer,
    tree: Address,
    commitments: &[InputCommitment],
) -> Result<Vec<SpendProof>, ClientError> {
    let leaves = commitments
        .iter()
        .map(|commitment| commitment.utxo_hash)
        .collect::<Vec<_>>();
    let nullifiers = commitments
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect::<Vec<_>>();
    let state_response = indexer.get_merkle_proofs(tree, leaves)?;
    let nullifier_response = indexer.get_non_inclusion_proofs(tree, nullifiers)?;
    validate_spend_proofs(
        tree,
        commitments,
        state_response.proofs,
        nullifier_response.proofs,
    )
}

async fn fetch_spend_proofs_async(
    indexer: &AsyncZolanaIndexer,
    tree: Address,
    commitments: &[InputCommitment],
) -> Result<Vec<SpendProof>, ClientError> {
    let leaves = commitments
        .iter()
        .map(|commitment| commitment.utxo_hash)
        .collect::<Vec<_>>();
    let nullifiers = commitments
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect::<Vec<_>>();
    let (state_response, nullifier_response) = tokio::try_join!(
        indexer.get_merkle_proofs(tree, leaves),
        indexer.get_non_inclusion_proofs(tree, nullifiers),
    )?;
    validate_spend_proofs(
        tree,
        commitments,
        state_response.proofs,
        nullifier_response.proofs,
    )
}

fn validate_spend_proofs(
    tree: Address,
    commitments: &[InputCommitment],
    state_proofs: Vec<crate::rpc::MerkleProof>,
    nullifier_proofs: Vec<crate::rpc::NonInclusionProof>,
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

/// Poll the RPC until the signature reaches confirmed commitment.
fn wait_for_rpc_confirmation<R: Rpc>(
    rpc: &R,
    signature: Signature,
    config: IndexerPollConfig,
) -> Result<(), ClientError> {
    let started = Instant::now();
    loop {
        if rpc.confirm_transaction(signature)? {
            return Ok(());
        }
        if started.elapsed() >= config.timeout {
            return Err(ClientError::Rpc(format!(
                "signature not confirmed: {signature}"
            )));
        }
        sleep(config.poll_interval);
    }
}

async fn wait_for_rpc_confirmation_async<R: AsyncRpc>(
    rpc: &R,
    signature: Signature,
    config: IndexerPollConfig,
) -> Result<(), ClientError> {
    let started = Instant::now();
    loop {
        if rpc.confirm_transaction(signature).await? {
            return Ok(());
        }
        if started.elapsed() >= config.timeout {
            return Err(ClientError::Rpc(format!(
                "signature not confirmed: {signature}"
            )));
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

/// Poll the indexer until the sent transaction is visible under any output
/// `view_tag` from the confirmed `TRANSACT` instruction. The indexer lags the
/// chain, so a plain on-chain confirmation is not enough for a caller that
/// reads state back immediately.
fn wait_for_indexed_transaction(
    indexer: &ZolanaIndexer,
    tags: &[[u8; 32]],
    signature: Signature,
    config: IndexerPollConfig,
) -> Result<(), ClientError> {
    if tags.is_empty() {
        return Err(ClientError::Rpc(
            "confirmed TRANSACT instruction has no output view tags".into(),
        ));
    }
    let started = Instant::now();
    loop {
        let response = indexer.get_shielded_transactions_by_tags(tags.to_vec(), None, Some(50))?;
        if response
            .transactions
            .iter()
            .any(|item| item.tx_signature == signature)
        {
            return Ok(());
        }
        if started.elapsed() >= config.timeout {
            return Err(ClientError::IndexerTimeout);
        }
        sleep(config.poll_interval);
    }
}

async fn wait_for_indexed_transaction_async(
    indexer: &AsyncZolanaIndexer,
    tags: &[[u8; 32]],
    signature: Signature,
    config: IndexerPollConfig,
) -> Result<(), ClientError> {
    if tags.is_empty() {
        return Err(ClientError::Rpc(
            "confirmed TRANSACT instruction has no output view tags".into(),
        ));
    }
    let started = Instant::now();
    loop {
        let response = indexer
            .get_shielded_transactions_by_tags(tags.to_vec(), None, Some(50))
            .await?;
        if response
            .transactions
            .iter()
            .any(|item| item.tx_signature == signature)
        {
            return Ok(());
        }
        if started.elapsed() >= config.timeout {
            return Err(ClientError::IndexerTimeout);
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Arc, Mutex},
        thread,
    };

    use serde_json::{json, Value};
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use zolana_keypair::ShieldedKeypair;
    use zolana_transaction::{AssetRegistry, Data, Utxo, Wallet, WalletUtxo, SOL_MINT};

    use super::*;
    use crate::{
        actions::transaction::sign_shielded_transaction_sync,
        actions::{create_withdrawal, WithdrawalParams},
        prover::CompressedCommitments,
        rpc::{MerkleContext, MerkleProof, NonInclusionProof},
        wallet_authority::LocalWalletAuthority,
    };

    #[test]
    fn confirm_private_transaction_sync_waits_for_indexer() {
        let payer = Keypair::new();
        let sender = ShieldedKeypair::new().expect("sender");
        let tree = Address::new_from_array([6u8; 32]);
        let wallet = wallet_with_tree(sender.clone(), tree, 10);
        let authority = LocalWalletAuthority::new(Pubkey::default(), &sender);
        let recipient = Pubkey::new_unique();
        let shielded = sign_shielded_transaction_sync(
            create_withdrawal(WithdrawalParams {
                wallet: &wallet,
                payer: Address::new_from_array(payer.pubkey().to_bytes()),
                recipient,
                asset: SOL_MINT,
                amount: 4,
            })
            .expect("create")
            .transaction,
            &wallet,
            &authority,
        )
        .expect("sign");
        let commitment = shielded.transaction.input_commitments().unwrap().remove(0);
        let signature = Signature::from([5u8; 64]);
        let server = MockIndexerServer::respond_with(vec![
            merkle_response(tree, commitment.utxo_hash),
            nullifier_response(tree, commitment.nullifier),
            indexed_transaction_response(signature),
        ]);
        let rpc = MockSubmitRpc::new(signature);
        let sent = rpc.sent.clone();
        let client = ZolanaClient::new(
            rpc,
            ZolanaIndexer::new(server.url()),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new(server.url()),
            AsyncProverClient::new("http://unused.invalid".to_string()),
            tree,
        )
        .with_compute_unit_price(25_000);

        let transaction = client
            .finish_submission_sync_with(&shielded, &payer, Hash::default(), |_| {
                Ok(ProofCompressed {
                    a: [0u8; 32],
                    b: [0u8; 64],
                    c: [0u8; 32],
                    commitment: Some(CompressedCommitments {
                        commitment: [0u8; 32],
                        commitment_pok: [0u8; 32],
                    }),
                })
            })
            .expect("finish");
        let result = client.rpc().send_transaction(&transaction).expect("send");
        client
            .confirm_private_transaction_sync(result)
            .expect("indexed");

        assert_eq!(result, signature);
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].message.instructions.len(), 3);
        let requests = server.requests();
        assert_eq!(
            requests,
            [
                "/get_merkle_proofs",
                "/get_non_inclusion_proofs",
                "/get_shielded_transactions_by_tags",
            ]
        );
    }

    #[test]
    fn submit_validation_binds_fee_payer_and_tree() {
        let payer = Keypair::new();
        let payer_hash = sha256_be(&payer.pubkey().to_bytes());
        let tree = Address::new_from_array([7u8; 32]);

        validate_fee_payer(&payer_hash, &payer).expect("matching payer");
        validate_transaction_tree(tree, tree).expect("matching tree");

        let other_payer = Keypair::new();
        assert!(matches!(
            validate_fee_payer(&payer_hash, &other_payer),
            Err(ClientError::FeePayerMismatch)
        ));
        assert!(matches!(
            validate_transaction_tree(tree, Address::default()),
            Err(ClientError::TreeMismatch { .. })
        ));
    }

    #[test]
    fn spend_proofs_are_bound_to_requested_commitments_and_tree() {
        let tree = Address::new_from_array([8u8; 32]);
        let commitment = InputCommitment {
            index: 0,
            utxo_hash: [1u8; 32],
            nullifier: [2u8; 32],
        };
        let proofs = validate_spend_proofs(
            tree,
            core::slice::from_ref(&commitment),
            vec![state_proof(tree, commitment.utxo_hash)],
            vec![nullifier_proof(tree, commitment.nullifier)],
        )
        .expect("matching proofs");
        assert_eq!(proofs.len(), 1);

        assert!(matches!(
            validate_spend_proofs(
                tree,
                core::slice::from_ref(&commitment),
                vec![state_proof(tree, [9u8; 32])],
                vec![nullifier_proof(tree, commitment.nullifier)],
            ),
            Err(ClientError::StateProofLeafMismatch { index: 0 })
        ));
        assert!(matches!(
            validate_spend_proofs(
                tree,
                core::slice::from_ref(&commitment),
                Vec::new(),
                vec![nullifier_proof(tree, commitment.nullifier)],
            ),
            Err(ClientError::IncompleteInputProofs {
                expected: 1,
                state: 0,
                nullifier: 1,
            })
        ));
    }

    #[test]
    fn submit_instructions_put_compute_budget_before_transact() {
        let transact_program = Pubkey::new_unique();
        let transact = Instruction {
            program_id: transact_program,
            accounts: Vec::new(),
            data: Vec::new(),
        };

        let default = submit_instructions(1_000_000, None, transact.clone());
        assert_eq!(default.len(), 2);
        assert_eq!(default[0].program_id, solana_compute_budget_interface::id());
        assert_eq!(default[1].program_id, transact_program);

        let prioritized = submit_instructions(1_000_000, Some(25_000), transact);
        assert_eq!(prioritized.len(), 3);
        assert_eq!(
            prioritized[0].program_id,
            solana_compute_budget_interface::id()
        );
        assert_eq!(
            prioritized[1].program_id,
            solana_compute_budget_interface::id()
        );
        assert_eq!(prioritized[2].program_id, transact_program);
    }

    #[test]
    fn confirm_private_transaction_sync_times_out_when_indexer_lags() {
        let signature = Signature::from([9u8; 64]);
        let server = MockIndexerServer::respond_with(vec![rpc_result(json!({
            "context": { "slot": 12 },
            "transactions": [],
            "next_cursor": null,
        }))]);
        let rpc = MockSubmitRpc::new(signature);
        let client = ZolanaClient::new(
            rpc,
            ZolanaIndexer::new(server.url()),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new(server.url()),
            AsyncProverClient::new("http://unused.invalid".to_string()),
            Address::new_from_array([8u8; 32]),
        )
        .with_indexer_poll_config(IndexerPollConfig {
            poll_interval: Duration::ZERO,
            timeout: Duration::ZERO,
        });
        let error = client
            .confirm_private_transaction_sync(signature)
            .expect_err("empty indexer response should time out");
        let _ = server.requests();

        assert!(matches!(error, ClientError::IndexerTimeout));
    }

    fn state_proof(tree: Address, leaf: [u8; 32]) -> MerkleProof {
        MerkleProof {
            leaf,
            merkle_context: MerkleContext { tree_type: 0, tree },
            path: vec![[0u8; 32]; crate::rpc::STATE_TREE_HEIGHT],
            leaf_index: 0,
            root: [3u8; 32],
            root_seq: 1,
            root_index: 0,
        }
    }

    fn nullifier_proof(tree: Address, leaf: [u8; 32]) -> NonInclusionProof {
        NonInclusionProof {
            leaf,
            merkle_context: MerkleContext { tree_type: 1, tree },
            path: vec![[0u8; 32]; crate::rpc::NULLIFIER_TREE_HEIGHT],
            low_element: [0u8; 32],
            low_element_index: 0,
            high_element: [u8::MAX; 32],
            high_element_index: 1,
            root: [4u8; 32],
            root_seq: 1,
            root_index: 0,
        }
    }

    fn wallet_with_tree(keypair: ShieldedKeypair, tree: Address, amount: u64) -> Wallet {
        let mut wallet = Wallet::new(
            keypair.shielded_address().expect("shielded address"),
            AssetRegistry::default(),
        )
        .expect("wallet");
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding: [7u8; 31],
            zone_program_id: None,
            data: Data::default(),
        };
        let nullifier_key = &keypair.nullifier_key;
        let nullifier_pubkey = nullifier_key.pubkey().expect("nullifier pubkey");
        let hash = utxo
            .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32])
            .expect("utxo hash");
        let nullifier = utxo.nullifier(&hash, nullifier_key).expect("nullifier");
        wallet.utxos.push(WalletUtxo {
            utxo,
            output_context: zolana_transaction::instructions::transact::types::OutputContext {
                hash,
                tree,
                leaf_index: 0,
            },
            nullifier,
            data_hash: None,
            zone_data_hash: None,
            spent: false,
        });
        wallet
    }

    struct MockSubmitRpc {
        signature: Signature,
        view_tags: Vec<[u8; 32]>,
        sent: Arc<Mutex<Vec<SolanaTransaction>>>,
    }

    impl MockSubmitRpc {
        fn new(signature: Signature) -> Self {
            Self {
                signature,
                view_tags: vec![[0u8; 32]],
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Rpc for MockSubmitRpc {
        fn get_account(&self, _address: Address) -> Result<Option<Account>, ClientError> {
            Ok(None)
        }

        fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            Ok((Hash::new_from_array([4u8; 32]), 100))
        }

        fn send_transaction(
            &self,
            transaction: &SolanaTransaction,
        ) -> Result<Signature, ClientError> {
            self.sent.lock().unwrap().push(transaction.clone());
            Ok(self.signature)
        }

        fn confirm_transaction(&self, _signature: Signature) -> Result<bool, ClientError> {
            Ok(true)
        }

        fn transact_output_view_tags_from_signature(
            &self,
            _signature: Signature,
        ) -> Result<Vec<[u8; 32]>, ClientError> {
            Ok(self.view_tags.clone())
        }
    }

    fn merkle_response(tree: Address, leaf: [u8; 32]) -> Value {
        rpc_result(json!({
            "context": { "slot": 10 },
            "proofs": [{
                "leaf": encode_hash(leaf),
                "merkle_context": {
                    "tree_type": 0,
                    "tree": encode_address(tree),
                },
                "path": vec![encode_hash([0u8; 32]); crate::rpc::STATE_TREE_HEIGHT],
                "leaf_index": 0,
                "root": encode_hash([3u8; 32]),
                "root_seq": 1,
                "root_index": 0,
            }],
        }))
    }

    fn nullifier_response(tree: Address, leaf: [u8; 32]) -> Value {
        rpc_result(json!({
            "context": { "slot": 10 },
            "proofs": [{
                "leaf": encode_hash(leaf),
                "merkle_context": {
                    "tree_type": 1,
                    "tree": encode_address(tree),
                },
                "path": vec![encode_hash([0u8; 32]); crate::rpc::NULLIFIER_TREE_HEIGHT],
                "low_element": encode_hash([0u8; 32]),
                "low_element_index": 0,
                "high_element": encode_hash([u8::MAX; 32]),
                "high_element_index": 1,
                "root": encode_hash([4u8; 32]),
                "root_seq": 1,
                "root_index": 0,
            }],
        }))
    }

    fn indexed_transaction_response(signature: Signature) -> Value {
        rpc_result(json!({
            "context": { "slot": 11 },
            "transactions": [{
                "slot": 11,
                "tx_signature": signature.to_string(),
                "tx_viewing_pk": null,
                "output_slots": [],
                "nullifiers": [],
                "proofless": false,
            }],
            "next_cursor": null,
        }))
    }

    fn rpc_result(result: Value) -> Value {
        json!({
            "id": "test-account",
            "jsonrpc": "2.0",
            "result": result,
        })
    }

    fn encode_hash(hash: [u8; 32]) -> String {
        bs58::encode(hash).into_string()
    }

    fn encode_address(address: Address) -> String {
        bs58::encode(address.to_bytes()).into_string()
    }

    struct MockIndexerServer {
        url: String,
        requests: mpsc::Receiver<String>,
        handle: thread::JoinHandle<()>,
    }

    impl MockIndexerServer {
        fn respond_with(responses: Vec<Value>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock indexer");
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (request_tx, requests) = mpsc::channel();
            let handle = thread::spawn(move || {
                for response in responses {
                    let (mut stream, _) = listener.accept().expect("accept request");
                    request_tx
                        .send(read_request_path(&mut stream))
                        .expect("record request");
                    write_json_response(&mut stream, &response);
                }
            });
            Self {
                url,
                requests,
                handle,
            }
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn requests(self) -> Vec<String> {
            self.handle.join().expect("mock indexer thread");
            self.requests.try_iter().collect()
        }
    }

    fn read_request_path(stream: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut buffer = [0u8; 1024];
        let mut body_start = None;
        let mut content_length = 0usize;
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            assert_ne!(read, 0, "client closed before sending request");
            data.extend_from_slice(&buffer[..read]);
            if body_start.is_none() {
                if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                    body_start = Some(index + 4);
                    let headers = String::from_utf8_lossy(&data[..index]);
                    content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse().ok())
                        })
                        .unwrap_or(0);
                }
            }
            if let Some(start) = body_start {
                if data.len() >= start + content_length {
                    break;
                }
            }
        }
        let headers = String::from_utf8_lossy(&data);
        headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("request path")
            .to_string()
    }

    fn write_json_response(stream: &mut TcpStream, response: &Value) {
        let body = response.to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
        .expect("write response");
    }
}
