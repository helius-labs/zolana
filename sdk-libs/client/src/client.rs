//! High-level Zolana client.
//!
//! [`ZolanaClient`] owns Solana RPC, Photon, and the prover.
//! [`sign_private_transaction`] returns a signed native Solana transaction.
//! Submit that transaction through the client's RPC adapter, then confirm on-chain and wait
//! for Photon indexing with [`ZolanaClient::confirm_private_transaction`].

use std::{sync::OnceLock, thread::sleep, time::Duration};

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
use solana_transaction::{versioned::VersionedTransaction, Transaction as SolanaTransaction};
use solana_transaction_status_client_types::TransactionStatus;
use zolana_interface::instruction::{
    InterfaceTransfer, Transact, TransactInterfaceTransferAccounts, TransactIxData,
};
use zolana_transaction::instructions::{transact::SppProofInputs, types::InputUtxoContext};

use crate::{
    error::ClientError,
    indexer::{AsyncZolanaIndexer, ZolanaIndexer},
    prover::{
        transact::witness::{assemble, ProverInputs, SpendProof},
        AsyncProverClient, ProofCompressed, ProverClient,
    },
    retry::{IndexerPollConfig, IndexerRpcConfig},
    rpc::{
        AsyncRpc, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
        ProveResult, Rpc, ShieldedTransactionStream,
    },
};

/// A signed shielded transaction ready for proof assembly and submission.
///
/// Produced by `zolana_wallet::sign_shielded_transaction`; consumed by
/// [`ZolanaClient`]'s submission helpers.
pub struct SignedPrivateTransaction {
    pub transaction: SppProofInputs,
    pub settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
    pub input_tree: Address,
}

/// Compute-unit ceiling a private transaction is submitted with unless the
/// caller overrides it. A shielded `Transact` verifies a Groth16 proof on-chain,
/// which does not fit inside the default per-instruction budget.
pub const DEFAULT_TRANSACT_CU_LIMIT: u32 = 300_000;

/// Unified client for private transaction proving and submission helpers.
///
/// The caller should not have to thread Solana RPC, Photon, and prover handles
/// through each step. This client owns those services. Proving and native Solana
/// transaction construction happen during [`sign_private_transaction`]; submission
/// is the caller's RPC adapter.
pub struct ZolanaClient<R> {
    rpc: R,
    indexer: OnceLock<ZolanaIndexer>,
    prover: OnceLock<ProverClient>,
    blocking_indexer_url: Option<String>,
    blocking_prover_url: Option<String>,
    async_indexer: AsyncZolanaIndexer,
    async_prover: AsyncProverClient,
    output_tree: Address,
    cu_limit: u32,
    cu_price_micro_lamports: Option<u64>,
    indexer_config: IndexerRpcConfig,
    send_config: Option<RpcSendTransactionConfig>,
}

impl<R> ZolanaClient<R> {
    pub fn new(
        rpc: R,
        indexer: ZolanaIndexer,
        prover: ProverClient,
        async_indexer: AsyncZolanaIndexer,
        async_prover: AsyncProverClient,
        output_tree: Address,
    ) -> Self {
        Self {
            rpc,
            indexer: OnceLock::from(indexer),
            prover: OnceLock::from(prover),
            blocking_indexer_url: None,
            blocking_prover_url: None,
            async_indexer,
            async_prover,
            output_tree,
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            cu_price_micro_lamports: None,
            indexer_config: IndexerRpcConfig::default(),
            send_config: None,
        }
    }

    /// Build both async and blocking service adapters from their URLs.
    ///
    /// Blocking adapters are initialized on first blocking use so constructing
    /// an async client inside a Tokio runtime never creates a nested runtime.
    pub fn from_urls(
        rpc: R,
        indexer_url: impl AsRef<str>,
        prover_url: impl Into<String>,
        output_tree: Address,
    ) -> Self {
        let indexer_url = indexer_url.as_ref().to_string();
        let prover_url = prover_url.into();
        Self {
            rpc,
            indexer: OnceLock::new(),
            prover: OnceLock::new(),
            blocking_indexer_url: Some(indexer_url.clone()),
            blocking_prover_url: Some(prover_url.clone()),
            async_indexer: AsyncZolanaIndexer::new(indexer_url),
            async_prover: AsyncProverClient::new(prover_url),
            output_tree,
            cu_limit: DEFAULT_TRANSACT_CU_LIMIT,
            cu_price_micro_lamports: None,
            indexer_config: IndexerRpcConfig::default(),
            send_config: None,
        }
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
        self.indexer_config.poll = config;
        self
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = config;
        self
    }

    pub fn with_send_transaction_config(mut self, config: RpcSendTransactionConfig) -> Self {
        self.send_config = Some(config);
        self
    }

    pub fn output_tree(&self) -> Address {
        self.output_tree
    }

    pub fn rpc(&self) -> &R {
        &self.rpc
    }

    pub fn indexer(&self) -> &ZolanaIndexer {
        self.blocking_indexer()
    }

    fn blocking_indexer(&self) -> &ZolanaIndexer {
        self.indexer.get_or_init(|| {
            ZolanaIndexer::new(
                self.blocking_indexer_url
                    .as_deref()
                    .expect("blocking indexer URL is set when the client is deferred"),
            )
        })
    }

    fn blocking_prover(&self) -> &ProverClient {
        self.prover.get_or_init(|| {
            ProverClient::new(
                self.blocking_prover_url
                    .clone()
                    .expect("blocking prover URL is set when the client is deferred"),
            )
        })
    }
}

impl<R: Rpc> ZolanaClient<R> {
    /// Fetch the input merkle proofs from the indexer and prove the transaction
    /// with the client's prover, returning the assembled `transact` instruction
    /// data ready for the [`Transact`] builder.
    pub fn prove_transact(
        &self,
        input_tree: Address,
        proof_inputs: SppProofInputs,
        config: Option<IndexerRpcConfig>,
    ) -> Result<TransactIxData, ClientError> {
        let commitments = proof_inputs.input_utxo_hashes()?;
        let spend_proofs =
            fetch_spend_proofs(self.blocking_indexer(), input_tree, &commitments, config)?;
        let dummy_proofs = fetch_dummy_nullifier_proofs(
            self.blocking_indexer(),
            input_tree,
            &proof_inputs,
            config,
        )?;
        self.blocking_prover()
            .prove_transact(proof_inputs, &spend_proofs, &dummy_proofs)
    }

    pub fn finish_submission_unsigned_sync(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: Pubkey,
        recent_blockhash: Hash,
    ) -> Result<SolanaTransaction, ClientError> {
        validate_fee_payer_pubkey(&signed.transaction.payer, fee_payer)?;
        let owner_signers = signed.transaction.owner_signer_pubkeys()?;
        let commitments = signed.transaction.input_utxo_hashes()?;
        let spend_proofs = {
            let _t = crate::timing::Phase::start("fetch_spend_proofs", 0);
            fetch_spend_proofs(
                self.blocking_indexer(),
                signed.input_tree,
                &commitments,
                None,
            )?
        };
        let dummy_proofs = {
            let _t = crate::timing::Phase::start("fetch_dummy_nullifier_proofs", 0);
            fetch_dummy_nullifier_proofs(
                self.blocking_indexer(),
                signed.input_tree,
                &signed.transaction,
                None,
            )?
        };
        let assembled = assemble(signed.transaction.clone(), &spend_proofs, &dummy_proofs)?;
        let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
        let proof = {
            let _t = crate::timing::Phase::start("prove_transfer", 0);
            self.blocking_prover().prove_transfer(inputs)?
        };
        let proof = ProofCompressed::try_from(proof)?.to_transact_proof();
        build_unsigned_solana_transaction(
            ComputeBudgetConfig {
                cu_limit: self.cu_limit,
                cu_price_micro_lamports: self.cu_price_micro_lamports,
            },
            fee_payer,
            TransactTrees {
                input_tree: signed.input_tree,
                output_tree: self.output_tree,
            },
            owner_signers,
            signed.settlement_transfers.clone(),
            assembled.with_proof(proof),
            recent_blockhash,
        )
    }

    #[cfg(test)]
    fn finish_submission_unsigned_sync_with(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: Pubkey,
        recent_blockhash: Hash,
        prove: impl FnOnce(&ProverInputs) -> Result<ProofCompressed, ClientError>,
    ) -> Result<SolanaTransaction, ClientError> {
        validate_fee_payer_pubkey(&signed.transaction.payer, fee_payer)?;
        let owner_signers = signed.transaction.owner_signer_pubkeys()?;
        let commitments = signed.transaction.input_utxo_hashes()?;
        let spend_proofs = fetch_spend_proofs(
            self.blocking_indexer(),
            signed.input_tree,
            &commitments,
            None,
        )?;
        let dummy_proofs = fetch_dummy_nullifier_proofs(
            self.blocking_indexer(),
            signed.input_tree,
            &signed.transaction,
            None,
        )?;
        let assembled = assemble(signed.transaction.clone(), &spend_proofs, &dummy_proofs)?;
        let proof = prove(&assembled.prover_inputs)?.to_transact_proof();
        build_unsigned_solana_transaction(
            ComputeBudgetConfig {
                cu_limit: self.cu_limit,
                cu_price_micro_lamports: self.cu_price_micro_lamports,
            },
            fee_payer,
            TransactTrees {
                input_tree: signed.input_tree,
                output_tree: self.output_tree,
            },
            owner_signers,
            signed.settlement_transfers.clone(),
            assembled.with_proof(proof),
            recent_blockhash,
        )
    }

    /// Wait until Solana confirms the transaction and Photon has indexed a
    /// Rings event for it.
    ///
    /// Confirming first turns a transaction that failed on chain into a chain
    /// error, instead of an indexer timeout that blames the wrong subsystem.
    pub fn confirm_private_transaction_sync(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        wait_for_rpc_confirmation(self.rpc(), signature, self.indexer_config.poll)?;
        wait_for_indexed_transaction(self.blocking_indexer(), signature, self.indexer_config.poll)
    }
}

impl<R: AsyncRpc> ZolanaClient<R> {
    pub async fn finish_submission_unsigned(
        &self,
        signed: &SignedPrivateTransaction,
        fee_payer: Pubkey,
        recent_blockhash: Hash,
    ) -> Result<SolanaTransaction, ClientError> {
        validate_fee_payer_pubkey(&signed.transaction.payer, fee_payer)?;
        let owner_signers = signed.transaction.owner_signer_pubkeys()?;
        let commitments = signed.transaction.input_utxo_hashes()?;
        let spend_proofs =
            fetch_spend_proofs_async(&self.async_indexer, signed.input_tree, &commitments, None)
                .await?;
        let dummy_proofs = fetch_dummy_nullifier_proofs_async(
            &self.async_indexer,
            signed.input_tree,
            &signed.transaction,
            None,
        )
        .await?;
        let assembled = assemble(signed.transaction.clone(), &spend_proofs, &dummy_proofs)?;
        let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
        let proof = self.async_prover.prove_transfer(inputs).await?;
        let proof = ProofCompressed::try_from(proof)?.to_transact_proof();
        build_unsigned_solana_transaction(
            ComputeBudgetConfig {
                cu_limit: self.cu_limit,
                cu_price_micro_lamports: self.cu_price_micro_lamports,
            },
            fee_payer,
            TransactTrees {
                input_tree: signed.input_tree,
                output_tree: self.output_tree,
            },
            owner_signers,
            signed.settlement_transfers.clone(),
            assembled.with_proof(proof),
            recent_blockhash,
        )
    }

    /// Wait until Solana confirms the transaction and Photon has indexed a
    /// Rings event for it.
    ///
    /// Confirming first turns a transaction that failed on chain into a chain
    /// error, instead of an indexer timeout that blames the wrong subsystem.
    pub async fn confirm_private_transaction(
        &self,
        signature: Signature,
    ) -> Result<(), ClientError> {
        wait_for_rpc_confirmation_async(self.rpc(), signature, self.indexer_config.poll).await?;
        wait_for_indexed_transaction_async(&self.async_indexer, signature, self.indexer_config.poll)
            .await
    }
}

#[async_trait]
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
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.async_indexer
            .get_encrypted_utxos_by_tags(
                tags,
                cursor,
                limit,
                Some(config.unwrap_or(self.indexer_config)),
            )
            .await
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.async_indexer
            .get_shielded_transactions_by_tags(
                tags,
                cursor,
                limit,
                Some(config.unwrap_or(self.indexer_config)),
            )
            .await
    }

    async fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.async_indexer
            .get_shielded_transactions_by_signature(
                signature,
                Some(config.unwrap_or(self.indexer_config)),
            )
            .await
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.async_indexer
            .get_shielded_transactions_by_nullifiers(
                nullifiers,
                cursor,
                limit,
                Some(config.unwrap_or(self.indexer_config)),
            )
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
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.async_indexer
            .get_merkle_proofs(
                tree_account,
                leaves,
                Some(config.unwrap_or(self.indexer_config)),
            )
            .await
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.async_indexer
            .get_non_inclusion_proofs(
                tree_account,
                leaves,
                Some(config.unwrap_or(self.indexer_config)),
            )
            .await
    }

    async fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputUtxoContext],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        fetch_spend_proofs_async(
            &self.async_indexer,
            self.output_tree,
            input_utxo_commitments,
            Some(config.unwrap_or(self.indexer_config)),
        )
        .await
    }

    async fn get_input_merkle_proofs_for_tree(
        &self,
        input_tree: Address,
        input_utxo_commitments: &[InputUtxoContext],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        fetch_spend_proofs_async(
            &self.async_indexer,
            input_tree,
            input_utxo_commitments,
            Some(config.unwrap_or(self.indexer_config)),
        )
        .await
    }

    async fn prove(&self, transaction: SppProofInputs) -> Result<ProveResult, ClientError> {
        let commitments = transaction.input_utxo_hashes()?;
        let input_merkle_proofs = self.get_input_merkle_proofs(&commitments, None).await?;
        let dummy_proofs = fetch_dummy_nullifier_proofs_async(
            &self.async_indexer,
            self.output_tree,
            &transaction,
            None,
        )
        .await?;
        let assembled = assemble(transaction, &input_merkle_proofs, &dummy_proofs)?;
        let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
        let proof = self.async_prover.prove_transfer(inputs).await?;
        let circuit_id = 0;
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
        self.rpc.should_retry(error) || self.blocking_indexer().should_retry(error)
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.blocking_indexer().get_encrypted_utxos_by_tags(
            tags,
            cursor,
            limit,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.blocking_indexer().get_shielded_transactions_by_tags(
            tags,
            cursor,
            limit,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.blocking_indexer()
            .get_shielded_transactions_by_signature(
                signature,
                Some(config.unwrap_or(self.indexer_config)),
            )
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.blocking_indexer()
            .get_shielded_transactions_by_nullifiers(
                nullifiers,
                cursor,
                limit,
                Some(config.unwrap_or(self.indexer_config)),
            )
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        self.blocking_indexer()
            .subscribe_to_shielded_transactions_by_tags(tags)
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.blocking_indexer().get_merkle_proofs(
            tree_account,
            leaves,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.blocking_indexer().get_non_inclusion_proofs(
            tree_account,
            leaves,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_input_merkle_proofs(
        &self,
        input_utxo_commitments: &[InputUtxoContext],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        fetch_spend_proofs(
            self.blocking_indexer(),
            self.output_tree,
            input_utxo_commitments,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn get_input_merkle_proofs_for_tree(
        &self,
        input_tree: Address,
        input_utxo_commitments: &[InputUtxoContext],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        fetch_spend_proofs(
            self.blocking_indexer(),
            input_tree,
            input_utxo_commitments,
            Some(config.unwrap_or(self.indexer_config)),
        )
    }

    fn prove(&self, transaction: SppProofInputs) -> Result<ProveResult, ClientError> {
        let commitments = transaction.input_utxo_hashes()?;
        let input_merkle_proofs = self.get_input_merkle_proofs(&commitments, None)?;
        let dummy_proofs = fetch_dummy_nullifier_proofs(
            self.blocking_indexer(),
            self.output_tree,
            &transaction,
            None,
        )?;
        let assembled = assemble(transaction, &input_merkle_proofs, &dummy_proofs)?;
        let ProverInputs::Eddsa(inputs) = &assembled.prover_inputs;
        let proof = self.blocking_prover().prove_transfer(inputs)?;
        let circuit_id = 0;
        Ok(ProveResult {
            proof: ProofCompressed::try_from(proof)?,
            public_inputs: vec![assembled.public_input_hash],
            circuit_id,
        })
    }
}

struct TransactTrees {
    input_tree: Address,
    output_tree: Address,
}

struct ComputeBudgetConfig {
    cu_limit: u32,
    cu_price_micro_lamports: Option<u64>,
}

fn build_unsigned_solana_transaction(
    compute_budget: ComputeBudgetConfig,
    fee_payer: Pubkey,
    trees: TransactTrees,
    owner_signers: Vec<Pubkey>,
    settlement_transfers: Vec<TransactInterfaceTransferAccounts>,
    transact_data: zolana_interface::instruction::instruction_data::transact::TransactIxData,
    recent_blockhash: Hash,
) -> Result<SolanaTransaction, ClientError> {
    validate_settlement_transfers(&transact_data.interface_transfers, &settlement_transfers)?;
    let transact_ix = Transact {
        payer: fee_payer,
        input_tree: trees.input_tree,
        output_tree: trees.output_tree,
        owner_signers,
        interface_transfer_accounts: settlement_transfers,
        data: transact_data,
    }
    .instruction();
    let instructions = submit_instructions(
        compute_budget.cu_limit,
        compute_budget.cu_price_micro_lamports,
        transact_ix,
    );
    let mut message = Message::new(&instructions, Some(&fee_payer));
    message.recent_blockhash = recent_blockhash;
    Ok(SolanaTransaction::new_unsigned(message))
}

fn validate_settlement_transfers(
    interface_transfers: &[InterfaceTransfer],
    settlement_transfers: &[TransactInterfaceTransferAccounts],
) -> Result<(), ClientError> {
    if interface_transfers.len() != settlement_transfers.len() {
        return Err(ClientError::SettlementTransferCountMismatch {
            interface_transfers: interface_transfers.len(),
            account_groups: settlement_transfers.len(),
        });
    }
    for (index, (transfer, accounts)) in interface_transfers
        .iter()
        .zip(settlement_transfers)
        .enumerate()
    {
        if !matches!(
            (transfer, accounts),
            (
                InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SolWithdrawal { .. },
                TransactInterfaceTransferAccounts::Sol(_)
            ) | (
                InterfaceTransfer::SplDeposit { .. },
                TransactInterfaceTransferAccounts::SplDeposit(_)
            ) | (
                InterfaceTransfer::SplWithdrawal { .. },
                TransactInterfaceTransferAccounts::SplWithdrawal(_)
            )
        ) {
            return Err(ClientError::SettlementTransferTypeMismatch { index });
        }
    }
    Ok(())
}

fn validate_fee_payer_pubkey(
    expected_payer: &Address,
    fee_payer: Pubkey,
) -> Result<(), ClientError> {
    if expected_payer.to_bytes() != fee_payer.to_bytes() {
        return Err(ClientError::FeePayerMismatch);
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
    commitments: &[InputUtxoContext],
    config: Option<IndexerRpcConfig>,
) -> Result<Vec<SpendProof>, ClientError> {
    let leaves = commitments
        .iter()
        .map(|commitment| commitment.utxo_hash)
        .collect::<Vec<_>>();
    let nullifiers = commitments
        .iter()
        .map(|commitment| commitment.nullifier)
        .collect::<Vec<_>>();
    let state_response = indexer.get_merkle_proofs(tree, leaves, config)?;
    let nullifier_response = indexer.get_non_inclusion_proofs(tree, nullifiers, config)?;
    validate_spend_proofs(
        tree,
        commitments,
        state_response.proofs,
        nullifier_response.proofs,
    )
}

/// Fetch the non-inclusion witness for each padding (dummy) input slot's
/// nullifier, in slot order. The circuit checks non-inclusion for every slot,
/// dummies included.
fn fetch_dummy_nullifier_proofs(
    indexer: &ZolanaIndexer,
    tree: Address,
    transaction: &SppProofInputs,
    config: Option<IndexerRpcConfig>,
) -> Result<Vec<crate::rpc::NonInclusionProof>, ClientError> {
    let nullifiers = transaction.dummy_nullifiers()?;
    if nullifiers.is_empty() {
        return Ok(Vec::new());
    }
    Ok(indexer
        .get_non_inclusion_proofs(tree, nullifiers, config)?
        .proofs)
}

async fn fetch_dummy_nullifier_proofs_async(
    indexer: &AsyncZolanaIndexer,
    tree: Address,
    transaction: &SppProofInputs,
    config: Option<IndexerRpcConfig>,
) -> Result<Vec<crate::rpc::NonInclusionProof>, ClientError> {
    let nullifiers = transaction.dummy_nullifiers()?;
    if nullifiers.is_empty() {
        return Ok(Vec::new());
    }
    Ok(indexer
        .get_non_inclusion_proofs(tree, nullifiers, config)
        .await?
        .proofs)
}

async fn fetch_spend_proofs_async(
    indexer: &AsyncZolanaIndexer,
    tree: Address,
    commitments: &[InputUtxoContext],
    config: Option<IndexerRpcConfig>,
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
        indexer.get_merkle_proofs(tree, leaves, config),
        indexer.get_non_inclusion_proofs(tree, nullifiers, config),
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
    commitments: &[InputUtxoContext],
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
    retry: IndexerPollConfig,
) -> Result<(), ClientError> {
    for delay in std::iter::once(Duration::ZERO).chain(retry.backoff()) {
        if !delay.is_zero() {
            sleep(delay);
        }
        if rpc.confirm_transaction(signature)? {
            return Ok(());
        }
    }
    Err(ClientError::Rpc(format!(
        "signature not confirmed: {signature}"
    )))
}

async fn wait_for_rpc_confirmation_async<R: AsyncRpc>(
    rpc: &R,
    signature: Signature,
    retry: IndexerPollConfig,
) -> Result<(), ClientError> {
    for delay in std::iter::once(Duration::ZERO).chain(retry.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if rpc.confirm_transaction(signature).await? {
            return Ok(());
        }
    }
    Err(ClientError::Rpc(format!(
        "signature not confirmed: {signature}"
    )))
}

/// Poll Photon until it has indexed a Rings event for `signature`. Photon lags
/// the chain, so an on-chain confirmation alone is not enough for a caller that
/// reads its own outputs back immediately.
///
/// Every Rings event of one Solana transaction is persisted in a single
/// database transaction, so a single visible event proves the whole transaction
/// is indexed. Matching the event against the transaction's view tags would add
/// no guarantee and would reject legitimate transactions whose events share a
/// tag.
fn wait_for_indexed_transaction(
    indexer: &ZolanaIndexer,
    signature: Signature,
    retry: IndexerPollConfig,
) -> Result<(), ClientError> {
    let mut last_error = None;
    for delay in std::iter::once(Duration::ZERO).chain(retry.backoff()) {
        if !delay.is_zero() {
            sleep(delay);
        }
        match indexer.get_shielded_transactions_by_signature(signature, None) {
            Ok(response) if !response.transactions.is_empty() => return Ok(()),
            Ok(_) => last_error = None,
            Err(error) if indexer.should_retry(&error) => last_error = Some(error.to_string()),
            Err(error) => return Err(error),
        }
    }
    Err(indexer_poll_timeout(retry, last_error))
}

async fn wait_for_indexed_transaction_async(
    indexer: &AsyncZolanaIndexer,
    signature: Signature,
    retry: IndexerPollConfig,
) -> Result<(), ClientError> {
    let mut last_error = None;
    for delay in std::iter::once(Duration::ZERO).chain(retry.backoff()) {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        match indexer
            .get_shielded_transactions_by_signature(signature, None)
            .await
        {
            Ok(response) if !response.transactions.is_empty() => return Ok(()),
            Ok(_) => last_error = None,
            Err(error) if indexer.should_retry(&error) => last_error = Some(error.to_string()),
            Err(error) => return Err(error),
        }
    }
    Err(indexer_poll_timeout(retry, last_error))
}

/// Classify an exhausted poll by how the *final* attempt went, since that is
/// the freshest evidence of what the indexer is doing now: an attempt that
/// answered without the transaction means the indexer is behind, and one that
/// failed means it never answered, which is not a lag report the caller should
/// act on. Earlier failures inside the window are deliberately not reported --
/// a blip the indexer recovered from should not be blamed for a genuine lag.
fn indexer_poll_timeout(retry: IndexerPollConfig, last_error: Option<String>) -> ClientError {
    match last_error {
        Some(last_error) => ClientError::PollTimedOut {
            attempts: retry.num_retries.saturating_add(1),
            last_error: Some(last_error),
        },
        None => ClientError::IndexerTimeout,
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
    use crate::rpc::{MerkleContext, MerkleProof, NonInclusionProof};
    use zolana_interface::instruction::{
        InterfaceTransfer, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
        TransactSplDepositAccounts,
    };
    use zolana_transaction::instructions::{
        transact::{ConfidentialTransfer, SettlementTarget},
        types::SppProofInputUtxo,
    };

    #[tokio::test]
    async fn from_urls_is_safe_inside_an_async_runtime() {
        let tree = Address::new_from_array([42u8; 32]);
        let client =
            ZolanaClient::from_urls((), "http://127.0.0.1:8784", "http://127.0.0.1:3001", tree);

        assert_eq!(client.output_tree(), tree);
        assert!(
            client.indexer.get().is_none(),
            "blocking indexer must be initialized lazily"
        );
        assert!(
            client.prover.get().is_none(),
            "blocking prover must be initialized lazily"
        );
    }

    #[test]
    fn settlement_accounts_accept_duplicate_sol_recipients_and_mixed_directions() {
        let spl = TransactSplDepositAccounts {
            mint: Pubkey::new_unique(),
            spl_interface: Pubkey::new_unique(),
            token_authority: Pubkey::new_unique(),
            user_token_account: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
        };
        let interface_transfers = [
            InterfaceTransfer::SolWithdrawal { amount: 7 },
            InterfaceTransfer::SplDeposit {
                amount: 11,
                spl_interface_bump: 42,
            },
            InterfaceTransfer::SolWithdrawal { amount: 3 },
        ];
        let settlement_transfers = [
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                recipient: Pubkey::new_unique(),
            }),
            TransactInterfaceTransferAccounts::SplDeposit(spl),
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                recipient: Pubkey::new_unique(),
            }),
        ];

        validate_settlement_transfers(&interface_transfers, &settlement_transfers)
            .expect("ordered duplicate-asset account groups are valid");
    }

    #[test]
    fn settlement_accounts_reject_count_and_type_mismatches() {
        let sol_accounts = TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
            recipient: Pubkey::new_unique(),
        });
        assert!(matches!(
            validate_settlement_transfers(&[InterfaceTransfer::SolWithdrawal { amount: 1 }], &[],),
            Err(ClientError::SettlementTransferCountMismatch {
                interface_transfers: 1,
                account_groups: 0,
            })
        ));
        assert!(matches!(
            validate_settlement_transfers(
                &[InterfaceTransfer::SplWithdrawal {
                    amount: 1,
                    spl_interface_bump: 42,
                }],
                &[sol_accounts],
            ),
            Err(ClientError::SettlementTransferTypeMismatch { index: 0 })
        ));
    }

    #[test]
    fn confirm_private_transaction_sync_waits_for_indexer() {
        let payer = Keypair::new();
        let sender = ShieldedKeypair::from_solana_keypair(&payer).expect("sender");
        let tree = Address::new_from_array([6u8; 32]);
        let wallet = wallet_with_tree(sender.clone(), tree, 10);
        let recipient = Pubkey::new_unique();
        let input = SppProofInputUtxo::new(
            wallet.utxos.first().expect("funded utxo").utxo.clone(),
            &sender,
        );
        let mut transfer = ConfidentialTransfer::new(
            sender.shielded_address().expect("shielded address"),
            vec![input],
            payer.pubkey(),
        );
        transfer
            .withdraw(
                SOL_MINT,
                4,
                SettlementTarget::Sol {
                    user_sol_account: recipient,
                },
            )
            .expect("withdraw");
        let proof_inputs = transfer
            .sign(&sender, &AssetRegistry::default())
            .expect("sign");
        let shielded = SignedPrivateTransaction {
            transaction: proof_inputs,
            settlement_transfers: vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )],
            input_tree: tree,
        };
        let commitment = shielded.transaction.input_utxo_hashes().unwrap().remove(0);
        let signature = Signature::from([5u8; 64]);
        let server = MockIndexerServer::respond_with(vec![
            merkle_response(tree, commitment.utxo_hash),
            nullifier_response(tree, commitment.nullifier),
            indexed_transaction_by_signature_response(signature),
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

        let blockhash = Hash::default();
        let mut transaction = client
            .finish_submission_unsigned_sync_with(&shielded, payer.pubkey(), blockhash, |_| {
                Ok(ProofCompressed {
                    a: [0u8; 32],
                    b: [0u8; 64],
                    c: [0u8; 32],
                    commitment: None,
                })
            })
            .expect("finish");
        transaction
            .try_sign(&[&payer], blockhash)
            .expect("sign native transaction");
        let result = Rpc::send_transaction(client.rpc(), &transaction).expect("send");
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
                "/get_shielded_transactions_by_signature",
            ]
        );
    }

    #[test]
    fn submit_validation_binds_fee_payer() {
        let payer = Keypair::new();
        let payer_address = Address::new_from_array(payer.pubkey().to_bytes());
        validate_fee_payer_pubkey(&payer_address, payer.pubkey()).expect("matching payer");

        let other_payer = Keypair::new();
        assert!(matches!(
            validate_fee_payer_pubkey(&payer_address, other_payer.pubkey()),
            Err(ClientError::FeePayerMismatch)
        ));
    }

    #[test]
    fn spend_proofs_are_bound_to_requested_commitments_and_tree() {
        let tree = Address::new_from_array([8u8; 32]);
        let commitment = InputUtxoContext {
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
            "context": { "block_time": 12, "slot": 1 },
            "transactions": [],
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
        .with_indexer_poll_config(IndexerPollConfig::new(0, 0, 0));
        let error = client
            .confirm_private_transaction_sync(signature)
            .expect_err("empty indexer response should time out");
        let _ = server.requests();

        assert!(matches!(error, ClientError::IndexerTimeout));
    }

    #[test]
    fn confirm_private_transaction_async_polls_until_the_event_is_indexed() {
        let signature = Signature::from([10u8; 64]);
        let server = MockIndexerServer::respond_with(vec![
            rpc_result(json!({
                "context": { "block_time": 12, "slot": 1 },
                "transactions": [],
            })),
            indexed_transaction_by_signature_response(signature),
        ]);
        let client = ZolanaClient::new(
            MockSubmitRpc::new(signature),
            ZolanaIndexer::new(server.url()),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new(server.url()),
            AsyncProverClient::new("http://unused.invalid".to_string()),
            Address::new_from_array([8u8; 32]),
        )
        .with_indexer_poll_config(IndexerPollConfig::new(1, 0, 0));

        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        runtime
            .block_on(client.confirm_private_transaction(signature))
            .expect("async lookup should poll past an empty response");

        assert_eq!(
            server.requests(),
            [
                "/get_shielded_transactions_by_signature",
                "/get_shielded_transactions_by_signature",
            ]
        );
    }

    #[test]
    fn confirm_private_transaction_sync_retries_transient_indexer_error() {
        let signature = Signature::from([15u8; 64]);
        let server = MockIndexerServer::respond_with(vec![
            rpc_error(-32603, "Internal error"),
            indexed_transaction_by_signature_response(signature),
        ]);
        let client = ZolanaClient::new(
            MockSubmitRpc::new(signature),
            ZolanaIndexer::new(server.url()),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new(server.url()),
            AsyncProverClient::new("http://unused.invalid".to_string()),
            Address::new_from_array([8u8; 32]),
        )
        .with_indexer_poll_config(IndexerPollConfig::new(1, 0, 0));

        client
            .confirm_private_transaction_sync(signature)
            .expect("retryable indexer error should be retried");

        assert_eq!(
            server.requests(),
            [
                "/get_shielded_transactions_by_signature",
                "/get_shielded_transactions_by_signature",
            ]
        );
    }

    /// An indexer that fails every attempt has not reported a lag, so reporting
    /// `IndexerTimeout` would send the caller looking for a transaction that
    /// was never queried successfully.
    #[test]
    fn confirm_private_transaction_sync_surfaces_the_last_transient_error() {
        let signature = Signature::from([20u8; 64]);
        let server = MockIndexerServer::respond_with(vec![
            rpc_error(-32603, "Internal error"),
            rpc_error(-32603, "Internal error"),
        ]);
        let client = ZolanaClient::new(
            MockSubmitRpc::new(signature),
            ZolanaIndexer::new(server.url()),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new(server.url()),
            AsyncProverClient::new("http://unused.invalid".to_string()),
            Address::new_from_array([8u8; 32]),
        )
        .with_indexer_poll_config(IndexerPollConfig::new(1, 0, 0));

        let error = client
            .confirm_private_transaction_sync(signature)
            .expect_err("an indexer that never answers must not look like a lag");

        assert_eq!(
            server.requests(),
            [
                "/get_shielded_transactions_by_signature",
                "/get_shielded_transactions_by_signature",
            ]
        );
        let ClientError::PollTimedOut {
            attempts,
            last_error,
        } = error
        else {
            panic!("expected PollTimedOut, got {error:?}");
        };
        assert_eq!(attempts, 2);
        assert!(last_error
            .expect("the last transient error is kept")
            .contains("Internal error"));
    }

    /// One signature can carry several Rings events, and nothing stops two of
    /// them from sharing a view tag. Confirmation only proves the transaction
    /// is indexed, so every event of that signature is an acceptable answer.
    #[test]
    fn confirm_private_transaction_sync_accepts_events_sharing_a_view_tag() {
        let signature = Signature::from([18u8; 64]);
        let server = MockIndexerServer::respond_with(vec![rpc_result(json!({
            "context": { "block_time": 12, "slot": 1 },
            "transactions": [
                { "event_index": 0, "transaction": indexed_transaction_json(signature) },
                { "event_index": 1, "transaction": indexed_transaction_json(signature) },
            ],
        }))]);
        let client = ZolanaClient::new(
            MockSubmitRpc::new(signature),
            ZolanaIndexer::new(server.url()),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new(server.url()),
            AsyncProverClient::new("http://unused.invalid".to_string()),
            Address::new_from_array([8u8; 32]),
        )
        .with_indexer_poll_config(IndexerPollConfig::new(0, 0, 0));

        client
            .confirm_private_transaction_sync(signature)
            .expect("events sharing a view tag are not an error");

        assert_eq!(
            server.requests(),
            ["/get_shielded_transactions_by_signature"]
        );
    }

    /// Confirmation no longer reads view tags, so the forwarders are the only
    /// thing keeping the capability reachable through `ZolanaClient`.
    #[test]
    fn client_forwards_transact_output_view_tags_to_the_rpc() {
        let signature = Signature::from([21u8; 64]);
        let expected = vec![[7u8; 32], [9u8; 32]];
        let client = ZolanaClient::new(
            MockSubmitRpc::new(signature).with_view_tags(expected.clone()),
            ZolanaIndexer::new("http://unused.invalid"),
            ProverClient::new("http://unused.invalid".to_string()),
            AsyncZolanaIndexer::new("http://unused.invalid"),
            AsyncProverClient::new("http://unused.invalid".to_string()),
            Address::new_from_array([8u8; 32]),
        );

        assert_eq!(
            Rpc::transact_output_view_tags_from_signature(&client, signature).expect("sync tags"),
            expected
        );

        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        assert_eq!(
            runtime
                .block_on(AsyncRpc::transact_output_view_tags_from_signature(
                    &client, signature
                ))
                .expect("async tags"),
            expected
        );
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
        let mut blinding = [0u8; 32];
        blinding[1..].fill(7);
        let utxo = Utxo {
            owner: keypair.signing_pubkey(),
            asset: SOL_MINT,
            amount,
            blinding,
            ring_program_id: None,
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
            ring_data_hash: None,
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
                view_tags: Vec::new(),
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn with_view_tags(mut self, view_tags: Vec<[u8; 32]>) -> Self {
            self.view_tags = view_tags;
            self
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

    #[async_trait]
    impl AsyncRpc for MockSubmitRpc {
        async fn confirm_transaction(&self, _signature: Signature) -> Result<bool, ClientError> {
            Ok(true)
        }

        async fn transact_output_view_tags_from_signature(
            &self,
            _signature: Signature,
        ) -> Result<Vec<[u8; 32]>, ClientError> {
            Ok(self.view_tags.clone())
        }
    }

    fn merkle_response(tree: Address, leaf: [u8; 32]) -> Value {
        rpc_result(json!({
            "context": { "block_time": 10, "slot": 1 },
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
            "context": { "block_time": 10, "slot": 1 },
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

    fn indexed_transaction_json(signature: Signature) -> Value {
        json!({
            "slot": 11,
            "tx_signature": signature.to_string(),
            "tx_viewing_pk": null,
            "output_slots": [{
                "view_tag": encode_hash([0u8; 32]),
                "output_context": {
                    "hash": encode_hash([1u8; 32]),
                    "tree": encode_address(Address::new_from_array([8u8; 32])),
                    "leaf_index": 0,
                },
                "payload": "",
            }],
            "messages": [],
            "nullifiers": [],
            "proofless": false,
        })
    }

    fn indexed_transaction_by_signature_response(signature: Signature) -> Value {
        rpc_result(json!({
            "context": { "block_time": 11, "slot": 1 },
            "transactions": [{
                "event_index": 0,
                "transaction": indexed_transaction_json(signature),
            }],
        }))
    }

    fn rpc_result(result: Value) -> Value {
        json!({
            "id": "test-account",
            "jsonrpc": "2.0",
            "result": result,
        })
    }

    fn rpc_error(code: i64, message: &str) -> Value {
        json!({
            "id": "test-account",
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message,
            },
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
        requests: mpsc::Receiver<MockRequest>,
        handle: thread::JoinHandle<()>,
    }

    struct MockRequest {
        path: String,
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
                        .send(read_request(&mut stream))
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
            self.requests
                .try_iter()
                .map(|request| request.path)
                .collect()
        }
    }

    fn read_request(stream: &mut TcpStream) -> MockRequest {
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
        let start = body_start.expect("request body");
        let headers = String::from_utf8_lossy(&data[..start]);
        let path = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("request path")
            .to_string();
        MockRequest { path }
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
