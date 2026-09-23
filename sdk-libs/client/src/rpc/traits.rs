use async_trait::async_trait;
use solana_account::Account;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Signer;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::TransactionStatus;
use zolana_transaction::{instructions::transact::SppProofInputs, utxo::SppProofInputUtxo};

use crate::{authority::ProofAuthority, error::ClientError, prover::transact::witness::SpendProof};

use super::{
    compute_budget::ComputeBudgetConfig,
    retry::IndexerRpcConfig,
    transaction::{compile_message, sign_transaction},
    types::{
        GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse, GetNonInclusionProofsResponse,
        GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse,
        GetRingSpendRecordResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
        ProveResult, RingHistoryOptions, RingMemberProofRequest, RingSpendRecordRequest,
        ShieldedTransactionStream,
    },
};

/// Combined Solana RPC, SPP indexer, and proving surface used by clients.
#[allow(unused_variables)]
pub trait Rpc {
    // ===== Accounts =====

    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Err(unsupported("get_account"))
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        Err(unsupported("get_multiple_accounts"))
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        Err(unsupported("get_program_accounts"))
    }

    // ===== Chain state =====

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        Err(unsupported("get_balance"))
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Err(unsupported("get_latest_blockhash"))
    }

    fn get_block_height(&self) -> Result<u64, ClientError> {
        Err(unsupported("get_block_height"))
    }

    fn get_slot(&self) -> Result<u64, ClientError> {
        Err(unsupported("get_slot"))
    }

    fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        Err(unsupported("get_transaction_slot"))
    }

    fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        Err(unsupported("get_signature_statuses"))
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        Err(unsupported("get_minimum_balance_for_rent_exemption"))
    }

    fn health(&self) -> Result<(), ClientError> {
        Err(unsupported("health"))
    }

    // ===== Transactions =====

    fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("send_transaction_with_config"))
    }

    fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("process_transaction"))
    }

    /// Build, sign, and send a v1 transaction: the only format this client
    /// sends, because it lifts the 1,232-byte legacy packet ceiling to 4,096
    /// bytes and carries its budget in the message header.
    fn create_and_send_transaction(
        &self,
        instructions: &[Instruction],
        payer: Address,
        signers: &[&dyn Signer],
        compute_budget: ComputeBudgetConfig,
    ) -> Result<Signature, ClientError> {
        let (blockhash, _) = self.get_latest_blockhash()?;
        let message = compile_message(&payer, instructions, blockhash, compute_budget)?;
        self.process_transaction(sign_transaction(message, signers)?)
    }

    // ===== Misc =====

    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        Err(unsupported("confirm_transaction"))
    }

    fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        Err(unsupported("transact_output_view_tags_from_signature"))
    }

    /// Whether `error` is transient for the post-submission confirmation poll
    /// (`wait_for_indexed_transaction`). Indexer data-plane polling
    /// (`IndexerPollConfig::poll_until`, the merkle-proof retry loop) deliberately
    /// retries every error and does not consult this.
    fn should_retry(&self, error: &ClientError) -> bool {
        false
    }

    // ===== Indexer (SPP) =====

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Err(unsupported("get_encrypted_utxos_by_tags"))
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_tags"))
    }

    fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_ring"))
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_signature"))
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_nullifiers"))
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        Err(unsupported("subscribe_to_shielded_transactions_by_tags"))
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        Err(unsupported("get_merkle_proofs"))
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        Err(unsupported("get_non_inclusion_proofs"))
    }

    fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ClientError> {
        Err(unsupported("get_ring_spend_record"))
    }

    fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
        Err(unsupported("get_ring_key_registry_entry"))
    }

    fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, ClientError> {
        Err(unsupported("get_ring_key_registry_register_proof"))
    }

    /// Resolve the state-inclusion and nullifier-non-inclusion proofs for each
    /// real input UTXO, returned in the same order as the inputs.
    ///
    /// No tree parameter: every input names the raw id of the tree it was
    /// published in, so an implementation groups by that and each returned
    /// proof names the account the id derives. A spend whose inputs span
    /// several trees goes through this one method.
    fn get_input_merkle_proofs(
        &self,
        input_utxos: &[&SppProofInputUtxo],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        Err(unsupported("get_input_merkle_proofs"))
    }

    // ===== Proving =====

    /// Build the SPP proof for a signed transaction (server-side proving).
    ///
    /// `authority` completes the assembled witness: it carries no nullifier
    /// secret until the owner fills in the inputs it holds.
    fn prove(
        &self,
        proof_inputs: SppProofInputs,
        authority: &dyn ProofAuthority,
    ) -> Result<ProveResult, ClientError> {
        Err(unsupported("prove"))
    }

    fn send_and_prove(&self, proof_inputs: SppProofInputs) -> Result<Signature, ClientError> {
        Err(unsupported("send_and_prove"))
    }
}

/// Async combined Solana RPC, SPP indexer, and proving surface for production clients.
#[async_trait]
#[allow(unused_variables)]
pub trait AsyncRpc: Send + Sync {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Err(unsupported("get_account"))
    }

    async fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        Err(unsupported("get_multiple_accounts"))
    }

    async fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        Err(unsupported("get_program_accounts"))
    }

    async fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        Err(unsupported("get_balance"))
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Err(unsupported("get_latest_blockhash"))
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        Err(unsupported("get_block_height"))
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        Err(unsupported("get_slot"))
    }

    async fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        Err(unsupported("get_transaction_slot"))
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        Err(unsupported("get_signature_statuses"))
    }

    async fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
    ) -> Result<u64, ClientError> {
        Err(unsupported("get_minimum_balance_for_rent_exemption"))
    }

    async fn health(&self) -> Result<(), ClientError> {
        Err(unsupported("health"))
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("send_transaction_with_config"))
    }

    async fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        Err(unsupported("process_transaction"))
    }

    async fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        Err(unsupported("confirm_transaction"))
    }

    async fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        Err(unsupported("transact_output_view_tags_from_signature"))
    }

    /// Whether `error` is transient for the post-submission confirmation poll
    /// (`wait_for_indexed_transaction_async`). Indexer data-plane polling
    /// (`IndexerPollConfig::poll_until`) deliberately retries every error and does
    /// not consult this.
    fn should_retry(&self, error: &ClientError) -> bool {
        false
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Err(unsupported("get_encrypted_utxos_by_tags"))
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_tags"))
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_ring"))
    }

    async fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_signature"))
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Err(unsupported("get_shielded_transactions_by_nullifiers"))
    }

    async fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        Err(unsupported("subscribe_to_shielded_transactions_by_tags"))
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        Err(unsupported("get_merkle_proofs"))
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        Err(unsupported("get_non_inclusion_proofs"))
    }

    async fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ClientError> {
        Err(unsupported("get_ring_spend_record"))
    }

    async fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
        Err(unsupported("get_ring_key_registry_entry"))
    }

    async fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, ClientError> {
        Err(unsupported("get_ring_key_registry_register_proof"))
    }

    async fn get_input_merkle_proofs(
        &self,
        input_utxos: &[&SppProofInputUtxo],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        Err(unsupported("get_input_merkle_proofs"))
    }

    /// See [`Rpc::prove`].
    async fn prove(
        &self,
        proof_inputs: SppProofInputs,
        authority: &dyn ProofAuthority,
    ) -> Result<ProveResult, ClientError> {
        Err(unsupported("prove"))
    }
}

fn unsupported(method: &'static str) -> ClientError {
    ClientError::UnsupportedRpcMethod(method)
}
