use std::time::{Duration, Instant};

use async_trait::async_trait;
use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_rpc_client::{
    api::config::RpcTransactionConfig, nonblocking::rpc_client::RpcClient as NonblockingRpcClient,
};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, TransactionStatus, UiTransactionEncoding,
};

use crate::{error::ClientError, rpc::AsyncRpc};

use super::{
    accounts::{filtered_program_accounts, pubkey_from_address, ProgramAccountsFilter},
    transaction::{
        instruction_groups_from_confirmed_transaction,
        transact_output_view_tags_from_instruction_groups, ConfirmedInstructionGroups,
    },
};

const DEFAULT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(30);

pub struct AsyncSolanaRpc {
    client: NonblockingRpcClient,
}

impl AsyncSolanaRpc {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_client(NonblockingRpcClient::new_with_commitment(
            url.into(),
            CommitmentConfig::confirmed(),
        ))
    }

    pub fn with_client(client: NonblockingRpcClient) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &NonblockingRpcClient {
        &self.client
    }

    /// Every returned account satisfies `filter`, an account outside it fails the call.
    pub async fn get_program_accounts_filtered(
        &self,
        program_id: Address,
        filter: &ProgramAccountsFilter,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        let accounts = self
            .client
            .get_program_ui_accounts_with_config(&program_id, filter.rpc_config())
            .await
            .map_err(|err| ClientError::Rpc(format!("get_program_accounts {program_id}: {err}")))?;
        filtered_program_accounts(&program_id, filter, accounts)
    }

    pub async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
        self.client
            .get_genesis_hash()
            .await
            .map(|hash| hash.to_bytes())
            .map_err(|_| ClientError::Rpc("genesis hash request failed".to_owned()))
    }

    pub async fn fetch_confirmed_transaction(
        &self,
        signature: &Signature,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta, ClientError> {
        let started = Instant::now();
        loop {
            let config = RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Json),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(1),
            };
            match self
                .client
                .get_transaction_with_config(signature, config)
                .await
            {
                Ok(transaction) => return Ok(transaction),
                Err(_) if started.elapsed() < DEFAULT_CONFIRMATION_TIMEOUT => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(err) => {
                    return Err(ClientError::Rpc(format!(
                        "get_transaction {signature}: {err}"
                    )));
                }
            }
        }
    }

    pub async fn fetch_confirmed_instruction_groups(
        &self,
        signature: &Signature,
    ) -> Result<ConfirmedInstructionGroups, ClientError> {
        let transaction = self.fetch_confirmed_transaction(signature).await?;
        instruction_groups_from_confirmed_transaction(transaction)
            .map_err(|err| err.for_signature(signature))
    }

    pub async fn transact_output_view_tags_from_signature(
        &self,
        signature: &Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        let groups = self.fetch_confirmed_instruction_groups(signature).await?;
        transact_output_view_tags_from_instruction_groups(&groups)
    }
}

#[async_trait]
impl AsyncRpc for AsyncSolanaRpc {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let pubkey = pubkey_from_address(&address);
        self.client
            .get_account_with_commitment(&pubkey, CommitmentConfig::confirmed())
            .await
            .map(|response| response.value)
            .map_err(|err| ClientError::Rpc(format!("get_account {pubkey}: {err}")))
    }

    async fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        let program = pubkey_from_address(&program_id);
        self.client
            .get_program_accounts(&program)
            .await
            .map(|accounts| {
                accounts
                    .into_iter()
                    .map(|(pubkey, account)| (Address::new_from_array(pubkey.to_bytes()), account))
                    .collect()
            })
            .map_err(|err| ClientError::Rpc(format!("get_program_accounts {program}: {err}")))
    }

    async fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        let pubkeys = addresses
            .iter()
            .map(pubkey_from_address)
            .collect::<Vec<_>>();
        self.client
            .get_multiple_accounts(&pubkeys)
            .await
            .map_err(|err| ClientError::Rpc(format!("get_multiple_accounts: {err}")))
    }

    async fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        let pubkey = pubkey_from_address(&address);
        self.client
            .get_balance(&pubkey)
            .await
            .map_err(|err| ClientError::Rpc(format!("get_balance {pubkey}: {err}")))
    }

    async fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
    ) -> Result<u64, ClientError> {
        self.client
            .get_minimum_balance_for_rent_exemption(data_len)
            .await
            .map_err(|err| {
                ClientError::Rpc(format!(
                    "get_minimum_balance_for_rent_exemption {data_len}: {err}"
                ))
            })
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.client
            .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())
            .await
            .map_err(|err| ClientError::Rpc(format!("get_latest_blockhash: {err}")))
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        self.client
            .get_block_height()
            .await
            .map_err(|err| ClientError::Rpc(format!("get_block_height: {err}")))
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        self.client
            .get_slot()
            .await
            .map_err(|err| ClientError::Rpc(format!("get_slot: {err}")))
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.client
            .get_signature_statuses(&signatures)
            .await
            .map(|response| response.value)
            .map_err(|err| ClientError::Rpc(format!("get_signature_statuses: {err}")))
    }

    async fn health(&self) -> Result<(), ClientError> {
        self.client
            .get_health()
            .await
            .map_err(|err| ClientError::Rpc(format!("get_health: {err}")))
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: solana_rpc_client_api::config::RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.client
            .send_transaction_with_config(transaction, config)
            .await
            .map_err(|source| ClientError::SolanaRpcTransaction {
                operation: "send_transaction_with_config",
                source,
            })
    }

    async fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        self.client
            .send_and_confirm_transaction(&transaction)
            .await
            .map_err(|source| ClientError::SolanaRpcTransaction {
                operation: "process_transaction",
                source,
            })
    }

    async fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.client
            .confirm_transaction(&signature)
            .await
            .map_err(|err| ClientError::Rpc(format!("confirm_transaction {signature}: {err}")))
    }

    async fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        AsyncSolanaRpc::transact_output_view_tags_from_signature(self, &signature).await
    }
}
