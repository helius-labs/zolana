use solana_account::Account;
use solana_address::Address;
use solana_hash::Hash;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::TransactionStatus;
use zolana_transaction::{instructions::transact::SppProofInputs, utxo::SppProofInputUtxo};

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::transact::witness::SpendProof,
    rpc::{
        AsyncRpc, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
        GetNonInclusionProofsResponse, GetRingKeyRegistryEntryResponse,
        GetRingKeyRegistryRegisterProofResponse, GetRingSpendRecordResponse,
        GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureResponse,
        GetShieldedTransactionsByTagsResponse, GetUserRecordsResponse, IndexerRpcConfig,
        ProveResult, RingHistoryOptions, RingMemberProofRequest, RingSpendRecordRequest, Rpc,
        ShieldedTransactionStream,
    },
};

use super::{BlockingIndexer, ZolanaClient};

/// Every call is the `async` client's, run to completion.
impl<R: Rpc + Send + Sync + 'static, I: BlockingIndexer> Rpc for ZolanaClient<R, I> {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.block_on(self.client.get_account(address))
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        self.block_on(self.client.get_multiple_accounts(addresses))
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        self.block_on(self.client.get_program_accounts(program_id))
    }

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        self.block_on(self.client.get_balance(address))
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.block_on(self.client.get_latest_blockhash())
    }

    fn get_block_height(&self) -> Result<u64, ClientError> {
        self.block_on(self.client.get_block_height())
    }

    fn get_slot(&self) -> Result<u64, ClientError> {
        self.block_on(self.client.get_slot())
    }

    fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        self.block_on(self.client.get_transaction_slot(signature))
    }

    fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.block_on(self.client.get_signature_statuses(signatures))
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        self.block_on(self.client.get_minimum_balance_for_rent_exemption(data_len))
    }

    fn health(&self) -> Result<(), ClientError> {
        self.block_on(self.client.health())
    }

    fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.block_on(
            self.client
                .send_transaction_with_config(transaction, config),
        )
    }

    fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.block_on(self.client.process_transaction(transaction))
    }

    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.block_on(self.client.confirm_transaction(signature))
    }

    fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        self.block_on(
            self.client
                .transact_output_view_tags_from_signature(signature),
        )
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        self.client.should_retry(error)
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.block_on(
            self.client
                .get_encrypted_utxos_by_tags(tags, cursor, limit, config),
        )
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.block_on(
            self.client
                .get_shielded_transactions_by_tags(tags, cursor, limit, config),
        )
    }

    fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.block_on(
            self.client
                .get_shielded_transactions_by_ring(options, config),
        )
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.block_on(
            self.client
                .get_shielded_transactions_by_signature(signature, config),
        )
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.block_on(
            self.client
                .get_shielded_transactions_by_nullifiers(nullifiers, cursor, limit, config),
        )
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        self.block_on(self.client.subscribe_to_shielded_transactions_by_tags(tags))
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.block_on(self.client.get_merkle_proofs(tree_account, leaves, config))
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.block_on(
            self.client
                .get_non_inclusion_proofs(tree_account, leaves, config),
        )
    }

    fn get_input_merkle_proofs(
        &self,
        input_utxos: &[&SppProofInputUtxo],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        self.block_on(self.client.get_input_merkle_proofs(input_utxos, config))
    }

    fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ClientError> {
        self.block_on(self.client.get_ring_spend_record(request))
    }

    fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
        self.block_on(self.client.get_ring_key_registry_entry(request))
    }

    fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, ClientError> {
        self.block_on(self.client.get_ring_key_registry_register_proof(request))
    }

    fn get_user_records(
        &self,
        owners: Vec<Address>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetUserRecordsResponse, ClientError> {
        self.block_on(self.client.get_user_records(owners, config))
    }

    fn prove(
        &self,
        transaction: SppProofInputs,
        authority: &dyn ProofAuthority,
    ) -> Result<ProveResult, ClientError> {
        self.block_on(self.client.prove(transaction, authority))
    }
}
