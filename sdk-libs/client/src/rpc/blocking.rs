//! A blocking [`Rpc`] serving as an [`AsyncRpc`], each call run on Tokio's
//! blocking pool, the way `zolana_api::OnBlockingPool` carries a blocking HTTP
//! client. The blocking `ZolanaClient` runs its `async` core over this.

use std::sync::Arc;

use async_trait::async_trait;
use solana_account::Account;
use solana_address::Address;
use solana_hash::Hash;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::TransactionStatus;
use zolana_transaction::utxo::SppProofInputUtxo;

use crate::prover::witness::{AsyncWitnessReader, InputWitnesses, WitnessReader};
use crate::{error::ClientError, prover::transact::witness::SpendProof};

use super::{
    traits::{AsyncRpc, Rpc},
    types::{
        GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse, GetNonInclusionProofsResponse,
        GetRingKeyRegistryEntryResponse, GetRingKeyRegistryRegisterProofResponse,
        GetRingSpendRecordResponse, GetShieldedTransactionsByNullifiersResponse,
        GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
        GetUserRecordsResponse, RingHistoryOptions, RingMemberProofRequest, RingSpendRecordRequest,
        ShieldedTransactionStream,
    },
    IndexerRpcConfig,
};

/// A blocking service as its `async` counterpart: every call runs on Tokio's
/// blocking pool. Clones share the service.
#[derive(Debug)]
pub struct Blocking<T>(Arc<T>);

impl<T> Clone for Blocking<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> Blocking<T> {
    pub fn new(inner: T) -> Self {
        Self(Arc::new(inner))
    }

    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<T: Send + Sync + 'static> Blocking<T> {
    async fn run<O: Send + 'static>(
        &self,
        call: impl FnOnce(&T) -> Result<O, ClientError> + Send + 'static,
    ) -> Result<O, ClientError> {
        let inner = Arc::clone(&self.0);
        tokio::task::spawn_blocking(move || call(&inner))
            .await
            .map_err(|error| ClientError::Rpc(format!("blocking call failed: {error}")))?
    }
}

/// [`Rpc::prove`] is not lifted: it borrows an authority for the call, which
/// cannot move to the pool. A `ZolanaClient` proves with its own prover.
#[async_trait]
impl<T: Rpc + Send + Sync + 'static> AsyncRpc for Blocking<T> {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.run(move |rpc| rpc.get_account(address)).await
    }

    async fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        self.run(move |rpc| rpc.get_multiple_accounts(addresses))
            .await
    }

    async fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        self.run(move |rpc| rpc.get_program_accounts(program_id))
            .await
    }

    async fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        self.run(move |rpc| rpc.get_balance(address)).await
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.run(|rpc| rpc.get_latest_blockhash()).await
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        self.run(|rpc| rpc.get_block_height()).await
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        self.run(|rpc| rpc.get_slot()).await
    }

    async fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        self.run(move |rpc| rpc.get_transaction_slot(signature))
            .await
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.run(move |rpc| rpc.get_signature_statuses(signatures))
            .await
    }

    async fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
    ) -> Result<u64, ClientError> {
        self.run(move |rpc| rpc.get_minimum_balance_for_rent_exemption(data_len))
            .await
    }

    async fn health(&self) -> Result<(), ClientError> {
        self.run(|rpc| rpc.health()).await
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        let transaction = transaction.clone();
        self.run(move |rpc| rpc.send_transaction_with_config(&transaction, config))
            .await
    }

    async fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.run(move |rpc| rpc.process_transaction(transaction))
            .await
    }

    async fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.run(move |rpc| rpc.confirm_transaction(signature))
            .await
    }

    async fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        self.run(move |rpc| rpc.transact_output_view_tags_from_signature(signature))
            .await
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        self.0.should_retry(error)
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.run(move |rpc| rpc.get_encrypted_utxos_by_tags(tags, cursor, limit, config))
            .await
    }

    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.run(move |rpc| rpc.get_shielded_transactions_by_tags(tags, cursor, limit, config))
            .await
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.run(move |rpc| rpc.get_shielded_transactions_by_ring(options, config))
            .await
    }

    async fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.run(move |rpc| rpc.get_shielded_transactions_by_signature(signature, config))
            .await
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.run(move |rpc| {
            rpc.get_shielded_transactions_by_nullifiers(nullifiers, cursor, limit, config)
        })
        .await
    }

    async fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        self.run(move |rpc| rpc.subscribe_to_shielded_transactions_by_tags(tags))
            .await
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.run(move |rpc| rpc.get_merkle_proofs(tree_account, leaves, config))
            .await
    }

    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.run(move |rpc| rpc.get_non_inclusion_proofs(tree_account, leaves, config))
            .await
    }

    async fn get_ring_spend_record(
        &self,
        request: RingSpendRecordRequest,
    ) -> Result<GetRingSpendRecordResponse, ClientError> {
        self.run(move |rpc| rpc.get_ring_spend_record(request))
            .await
    }

    async fn get_ring_key_registry_entry(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryEntryResponse, ClientError> {
        self.run(move |rpc| rpc.get_ring_key_registry_entry(request))
            .await
    }

    async fn get_ring_key_registry_register_proof(
        &self,
        request: RingMemberProofRequest,
    ) -> Result<GetRingKeyRegistryRegisterProofResponse, ClientError> {
        self.run(move |rpc| rpc.get_ring_key_registry_register_proof(request))
            .await
    }

    async fn get_user_records(
        &self,
        owners: Vec<Address>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetUserRecordsResponse, ClientError> {
        self.run(move |rpc| rpc.get_user_records(owners, config))
            .await
    }

    async fn get_input_merkle_proofs(
        &self,
        input_utxos: &[&SppProofInputUtxo],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        let inputs: Vec<SppProofInputUtxo> =
            input_utxos.iter().map(|input| (*input).clone()).collect();
        self.run(move |rpc| {
            let inputs: Vec<&SppProofInputUtxo> = inputs.iter().collect();
            rpc.get_input_merkle_proofs(&inputs, config)
        })
        .await
    }
}

impl<T: Rpc + WitnessReader + Send + Sync + 'static> AsyncWitnessReader for Blocking<T> {
    fn input_witnesses(
        &self,
        inputs: &[&SppProofInputUtxo],
        dummy_nullifiers: &[[u8; 32]],
        config: Option<IndexerRpcConfig>,
    ) -> impl std::future::Future<Output = Result<InputWitnesses, ClientError>> + Send {
        let inputs: Vec<SppProofInputUtxo> = inputs.iter().map(|input| (*input).clone()).collect();
        let dummy_nullifiers = dummy_nullifiers.to_vec();
        self.run(move |reader| {
            let inputs: Vec<&SppProofInputUtxo> = inputs.iter().collect();
            reader.input_witnesses(&inputs, &dummy_nullifiers, config)
        })
    }
}
