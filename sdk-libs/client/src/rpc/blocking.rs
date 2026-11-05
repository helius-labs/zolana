//! An [`AsyncRpc`] serving as a blocking [`Rpc`]: each call runs to
//! completion on a [`BlockingRuntime`]. The blocking indexer and client are
//! this over their `async` counterparts, so every method is written once, as
//! `async`. [`OnBlockingPool`](super::OnBlockingPool) is the other direction.

use std::{future::Future, sync::Arc};

use solana_account::Account;
use solana_address::Address;
use solana_hash::Hash;
use solana_rpc_client_api::config::RpcSendTransactionConfig;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::TransactionStatus;
use spr_api::BlockingRuntime;
use spr_transaction::{instructions::transact::SppProofInputs, utxo::SppProofInputUtxo};

use crate::{
    authority::ProofAuthority,
    error::ClientError,
    prover::{
        transact::witness::SpendProof,
        witness::{AsyncWitnessReader, InputWitnesses, WitnessReader},
    },
};

use super::{
    traits::{AsyncRpc, Rpc},
    types::{
        GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse, GetNonInclusionProofsResponse,
        GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureResponse,
        GetShieldedTransactionsByTagsResponse, GetUserRecordsResponse, HistoryFilters,
        PaginationToken, ProveResult, RingHistoryOptions, ShieldedTransactionStream,
    },
    IndexerRpcConfig, ProgramAccountsFilter,
};

/// An `async` service for blocking callers: every call runs to completion on
/// a runtime, so it is made from plain threads or from inside a multi-thread
/// runtime alike; only a `current_thread` runtime cannot host it. Clones share
/// the runtime.
#[derive(Clone, Debug)]
pub struct Blocking<T> {
    inner: T,
    runtime: Arc<BlockingRuntime>,
}

impl<T> Blocking<T> {
    /// `inner`, run on `runtime`.
    pub fn with_runtime(inner: T, runtime: Arc<BlockingRuntime>) -> Self {
        Self { inner, runtime }
    }

    /// `inner`, run on a runtime of its own.
    pub fn on_new_runtime(inner: T) -> Self {
        Self::with_runtime(inner, Arc::new(BlockingRuntime::new()))
    }

    /// The `async` service.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// The `async` service and the runtime it runs on.
    pub fn into_parts(self) -> (T, Arc<BlockingRuntime>) {
        (self.inner, self.runtime)
    }

    /// The runtime this service's calls run on, for a client built beside it.
    pub fn runtime(&self) -> Arc<BlockingRuntime> {
        Arc::clone(&self.runtime)
    }

    /// Run `future` to completion on this service's runtime.
    pub fn block_on<O>(
        &self,
        future: impl Future<Output = Result<O, ClientError>>,
    ) -> Result<O, ClientError> {
        self.runtime.block_on(future)
    }

    /// This service with `inner` replaced by `map(inner)`, on the same runtime.
    pub(crate) fn map<U>(self, map: impl FnOnce(T) -> U) -> Blocking<U> {
        Blocking {
            inner: map(self.inner),
            runtime: self.runtime,
        }
    }
}

impl<T: AsyncRpc> Rpc for Blocking<T> {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.block_on(self.inner.get_account(address))
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        self.block_on(self.inner.get_multiple_accounts(addresses))
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        self.block_on(self.inner.get_program_accounts(program_id))
    }

    fn get_program_accounts_filtered(
        &self,
        program_id: Address,
        filter: &ProgramAccountsFilter,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        self.block_on(self.inner.get_program_accounts_filtered(program_id, filter))
    }

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        self.block_on(self.inner.get_balance(address))
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.block_on(self.inner.get_latest_blockhash())
    }

    fn get_block_height(&self) -> Result<u64, ClientError> {
        self.block_on(self.inner.get_block_height())
    }

    fn get_slot(&self) -> Result<u64, ClientError> {
        self.block_on(self.inner.get_slot())
    }

    fn get_transaction_slot(&self, signature: Signature) -> Result<u64, ClientError> {
        self.block_on(self.inner.get_transaction_slot(signature))
    }

    fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.block_on(self.inner.get_signature_statuses(signatures))
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        self.block_on(self.inner.get_minimum_balance_for_rent_exemption(data_len))
    }

    fn health(&self) -> Result<(), ClientError> {
        self.block_on(self.inner.health())
    }

    fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.block_on(self.inner.send_transaction_with_config(transaction, config))
    }

    fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.block_on(self.inner.process_transaction(transaction))
    }

    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.block_on(self.inner.confirm_transaction(signature))
    }

    fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        self.block_on(
            self.inner
                .transact_output_view_tags_from_signature(signature),
        )
    }

    fn should_retry(&self, error: &ClientError) -> bool {
        self.inner.should_retry(error)
    }

    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        pagination_token: Option<PaginationToken>,
        limit: Option<u32>,
        filters: HistoryFilters,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        self.block_on(self.inner.get_encrypted_utxos_by_tags(
            tags,
            pagination_token,
            limit,
            filters,
            config,
        ))
    }

    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        pagination_token: Option<PaginationToken>,
        limit: Option<u32>,
        filters: HistoryFilters,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.block_on(self.inner.get_shielded_transactions_by_tags(
            tags,
            pagination_token,
            limit,
            filters,
            config,
        ))
    }

    fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.block_on(
            self.inner
                .get_shielded_transactions_by_ring(options, config),
        )
    }

    fn get_shielded_transactions_by_signature(
        &self,
        signature: Signature,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.block_on(
            self.inner
                .get_shielded_transactions_by_signature(signature, config),
        )
    }

    fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        pagination_token: Option<PaginationToken>,
        limit: Option<u32>,
        filters: HistoryFilters,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        self.block_on(self.inner.get_shielded_transactions_by_nullifiers(
            nullifiers,
            pagination_token,
            limit,
            filters,
            config,
        ))
    }

    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<ShieldedTransactionStream, ClientError> {
        self.block_on(self.inner.subscribe_to_shielded_transactions_by_tags(tags))
    }

    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        self.block_on(self.inner.get_merkle_proofs(tree_account, leaves, config))
    }

    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        self.block_on(
            self.inner
                .get_non_inclusion_proofs(tree_account, leaves, config),
        )
    }

    fn get_user_records(
        &self,
        owners: Vec<Address>,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetUserRecordsResponse, ClientError> {
        self.block_on(self.inner.get_user_records(owners, config))
    }

    fn get_input_merkle_proofs(
        &self,
        input_utxos: &[&SppProofInputUtxo],
        config: Option<IndexerRpcConfig>,
    ) -> Result<Vec<SpendProof>, ClientError> {
        self.block_on(self.inner.get_input_merkle_proofs(input_utxos, config))
    }

    fn prove(
        &self,
        proof_inputs: SppProofInputs,
        authority: &dyn ProofAuthority,
    ) -> Result<ProveResult, ClientError> {
        self.block_on(self.inner.prove(proof_inputs, authority))
    }
}

impl<T: AsyncRpc + AsyncWitnessReader> WitnessReader for Blocking<T> {
    fn transaction_proofs(
        &self,
        inputs: &[SppProofInputUtxo],
        config: Option<IndexerRpcConfig>,
    ) -> Result<InputWitnesses, ClientError> {
        self.block_on(AsyncWitnessReader::transaction_proofs(
            &self.inner,
            inputs,
            config,
        ))
    }

    fn input_witnesses(
        &self,
        inputs: &[&SppProofInputUtxo],
        dummy_nullifiers: &[[u8; 32]],
        config: Option<IndexerRpcConfig>,
    ) -> Result<InputWitnesses, ClientError> {
        self.block_on(AsyncWitnessReader::input_witnesses(
            &self.inner,
            inputs,
            dummy_nullifiers,
            config,
        ))
    }
}
