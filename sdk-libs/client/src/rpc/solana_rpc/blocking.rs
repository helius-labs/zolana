use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_rpc_client::{
    api::config::{RpcSendTransactionConfig, RpcTransactionConfig},
    rpc_client::RpcClient,
};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, TransactionStatus, UiTransactionEncoding,
};

use crate::{error::ClientError, rpc::Rpc};

use super::{
    accounts::{filtered_program_accounts, pubkey_from_address, ProgramAccountsFilter},
    transaction::{
        instruction_groups_from_confirmed_transaction,
        transact_output_view_tags_from_instruction_groups, ConfirmedInstructionGroups,
    },
    DEFAULT_POLL_INTERVAL,
};

pub struct SolanaRpc {
    client: RpcClient,
    confirmation_timeout: Duration,
    poll_interval: Duration,
}

impl SolanaRpc {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_client(RpcClient::new_with_commitment(
            url.into(),
            CommitmentConfig::confirmed(),
        ))
    }

    pub fn with_client(client: RpcClient) -> Self {
        Self {
            client,
            confirmation_timeout: Duration::from_secs(30),
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// Poll confirmations and transaction lookups every `interval`. A local
    /// validator confirms within milliseconds, so tests poll far more often
    /// than the default.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    /// Every returned account satisfies `filter`, an account outside it fails the call.
    pub fn get_program_accounts_filtered(
        &self,
        program_id: Address,
        filter: &ProgramAccountsFilter,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        let accounts = self
            .client
            .get_program_ui_accounts_with_config(&program_id, filter.rpc_config())
            .map_err(|err| ClientError::Rpc(format!("get_program_accounts {program_id}: {err}")))?;
        filtered_program_accounts(&program_id, filter, accounts)
    }

    pub fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
        self.client
            .get_genesis_hash()
            .map(|hash| hash.to_bytes())
            .map_err(|_| ClientError::Rpc("genesis hash request failed".to_owned()))
    }

    pub fn assert_executable(&self, program_id: &Pubkey) -> Result<(), ClientError> {
        let account = self
            .client
            .get_account(program_id)
            .map_err(|err| ClientError::Rpc(format!("get_account {program_id}: {err}")))?;
        if !account.executable {
            return Err(ClientError::Rpc(format!(
                "program is not executable: {program_id}"
            )));
        }
        Ok(())
    }

    pub fn airdrop(&mut self, pubkey: &Pubkey, lamports: u64) -> Result<Signature, ClientError> {
        let signature = self
            .client
            .request_airdrop(pubkey, lamports)
            .map_err(|err| ClientError::Rpc(format!("request_airdrop {pubkey}: {err}")))?;
        self.wait_for_signature(&signature)?;
        Ok(signature)
    }

    fn wait_for_signature(&self, signature: &Signature) -> Result<(), ClientError> {
        let started = Instant::now();
        while started.elapsed() < self.confirmation_timeout {
            let confirmed = self.client.confirm_transaction(signature).map_err(|err| {
                ClientError::Rpc(format!("confirm_transaction {signature}: {err}"))
            })?;
            if confirmed {
                return Ok(());
            }
            sleep(self.poll_interval);
        }
        Err(ClientError::Rpc(format!(
            "signature not confirmed: {signature}"
        )))
    }

    pub fn fetch_confirmed_instruction_groups(
        &self,
        signature: &Signature,
    ) -> Result<ConfirmedInstructionGroups, ClientError> {
        let transaction = self.fetch_confirmed_transaction(signature)?;
        instruction_groups_from_confirmed_transaction(transaction)
            .map_err(|err| err.for_signature(signature))
    }

    pub fn transact_output_view_tags_from_signature(
        &self,
        signature: &Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        let groups = self.fetch_confirmed_instruction_groups(signature)?;
        transact_output_view_tags_from_instruction_groups(&groups)
    }

    pub fn fetch_confirmed_transaction(
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
            match self.client.get_transaction_with_config(signature, config) {
                Ok(transaction) => return Ok(transaction),
                Err(_) if started.elapsed() < self.confirmation_timeout => {
                    sleep(self.poll_interval);
                }
                Err(err) => {
                    return Err(ClientError::Rpc(format!(
                        "get_transaction {signature}: {err}"
                    )));
                }
            }
        }
    }
}

impl Rpc for SolanaRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let pubkey = pubkey_from_address(&address);
        self.client
            .get_account_with_commitment(&pubkey, CommitmentConfig::confirmed())
            .map(|response| response.value)
            .map_err(|err| ClientError::Rpc(format!("get_account {pubkey}: {err}")))
    }

    fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        let program = pubkey_from_address(&program_id);
        self.client
            .get_program_accounts(&program)
            .map(|accounts| {
                accounts
                    .into_iter()
                    .map(|(pubkey, account)| (Address::new_from_array(pubkey.to_bytes()), account))
                    .collect()
            })
            .map_err(|err| ClientError::Rpc(format!("get_program_accounts {program}: {err}")))
    }

    fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        let pubkeys = addresses
            .iter()
            .map(pubkey_from_address)
            .collect::<Vec<_>>();
        self.client
            .get_multiple_accounts(&pubkeys)
            .map_err(|err| ClientError::Rpc(format!("get_multiple_accounts: {err}")))
    }

    fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        let pubkey = pubkey_from_address(&address);
        self.client
            .get_balance(&pubkey)
            .map_err(|err| ClientError::Rpc(format!("get_balance {pubkey}: {err}")))
    }

    fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, ClientError> {
        self.client
            .get_minimum_balance_for_rent_exemption(data_len)
            .map_err(|err| {
                ClientError::Rpc(format!(
                    "get_minimum_balance_for_rent_exemption {data_len}: {err}"
                ))
            })
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        self.client
            .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())
            .map_err(|err| ClientError::Rpc(format!("get_latest_blockhash: {err}")))
    }

    fn get_block_height(&self) -> Result<u64, ClientError> {
        self.client
            .get_block_height()
            .map_err(|err| ClientError::Rpc(format!("get_block_height: {err}")))
    }

    fn get_slot(&self) -> Result<u64, ClientError> {
        self.client
            .get_slot()
            .map_err(|err| ClientError::Rpc(format!("get_slot: {err}")))
    }

    fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.client
            .get_signature_statuses(&signatures)
            .map(|response| response.value)
            .map_err(|err| ClientError::Rpc(format!("get_signature_statuses: {err}")))
    }

    fn health(&self) -> Result<(), ClientError> {
        self.client
            .get_health()
            .map_err(|err| ClientError::Rpc(format!("get_health: {err}")))
    }

    fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        config: solana_rpc_client_api::config::RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        // Sends and returns; it does not confirm, matching the legacy
        // `send_transaction_with_config` above rather than the confirming
        // `process_transaction` below.
        self.client
            .send_transaction_with_config(transaction, config)
            .map_err(|source| ClientError::SolanaRpcTransaction {
                operation: "send_transaction_with_config",
                source,
            })
    }

    /// `RpcClient::send_and_confirm_transaction` with the status polled every
    /// `poll_interval` instead of every 500ms: send with preflight at the
    /// client's commitment, then poll until the transaction confirms, fails,
    /// or its blockhash expires.
    fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        let error = |source| ClientError::SolanaRpcTransaction {
            operation: "process_transaction",
            source,
        };
        let commitment = self.client.commitment();
        let signature = self
            .client
            .send_transaction_with_config(
                &transaction,
                RpcSendTransactionConfig {
                    preflight_commitment: Some(commitment.commitment),
                    ..RpcSendTransactionConfig::default()
                },
            )
            .map_err(error)?;
        let blockhash = transaction.message.recent_blockhash();
        loop {
            match self
                .client
                .get_signature_status_with_commitment(&signature, commitment)
                .map_err(error)?
            {
                Some(Ok(())) => return Ok(signature),
                Some(Err(failure)) => return Err(error(failure.into())),
                None => {
                    if !self
                        .client
                        .is_blockhash_valid(blockhash, CommitmentConfig::processed())
                        .map_err(error)?
                    {
                        return Err(ClientError::Rpc(format!(
                            "transaction {signature} was not confirmed before its blockhash expired"
                        )));
                    }
                    sleep(self.poll_interval);
                }
            }
        }
    }

    fn confirm_transaction(&self, signature: Signature) -> Result<bool, ClientError> {
        self.client
            .confirm_transaction(&signature)
            .map_err(|err| ClientError::Rpc(format!("confirm_transaction {signature}: {err}")))
    }

    fn transact_output_view_tags_from_signature(
        &self,
        signature: Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        SolanaRpc::transact_output_view_tags_from_signature(self, &signature)
    }
}
