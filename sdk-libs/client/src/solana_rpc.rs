//! Generic blocking Solana RPC backend.
//!
//! Wraps a `solana_rpc_client::RpcClient` and implements [`Rpc`] over
//! it. It can expose confirmed instruction groups for event parsers, but it
//! does not index shielded-pool state itself.

use std::{
    collections::BTreeSet,
    thread::sleep,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use solana_rpc_client::{
    api::config::RpcTransactionConfig, nonblocking::rpc_client::RpcClient as NonblockingRpcClient,
    rpc_client::RpcClient,
};
use solana_signature::Signature;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    EncodedTransaction, TransactionStatus, UiCompiledInstruction, UiInstruction, UiLoadedAddresses,
    UiMessage, UiTransactionEncoding,
};
use zolana_event::{InstructionGroup, ParsedInstruction};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{fetch_tag, TransactIxData},
        tag,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

use crate::{
    error::ClientError,
    rpc::{AsyncRpc, Rpc},
};

fn pubkey_from_address(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

pub struct SolanaRpc {
    client: RpcClient,
    confirmation_timeout: Duration,
}

pub struct AsyncSolanaRpc {
    client: NonblockingRpcClient,
}

#[derive(Clone, Debug)]
pub struct ConfirmedInstructionGroups {
    pub groups: Vec<InstructionGroup>,
}

const DEFAULT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Unique `view_tag`s from a confirmed shielded-pool `TRANSACT` instruction,
/// found either as the transaction's outer instruction (a direct `Transact`
/// call) or as an inner instruction (a program CPIing into `transact`, e.g.
/// the zk-program-swap `Make`/`Take`/`Cancel` wrappers).
pub fn transact_output_view_tags_from_instruction_groups(
    groups: &ConfirmedInstructionGroups,
) -> Result<Vec<[u8; 32]>, ClientError> {
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    for group in &groups.groups {
        for instruction in std::iter::once(&group.outer).chain(group.inner.iter()) {
            if let Some(tags) = transact_view_tags(instruction, program_id)? {
                return Ok(tags);
            }
        }
    }
    Err(ClientError::Rpc(
        "confirmed transaction has no shielded-pool TRANSACT instruction".into(),
    ))
}

/// Returns the output `view_tag`s if `instruction` is a `TRANSACT` call to
/// `program_id`, `None` if it is unrelated, or an error if it matches but its
/// payload cannot be decoded.
fn transact_view_tags(
    instruction: &ParsedInstruction,
    program_id: Pubkey,
) -> Result<Option<Vec<[u8; 32]>>, ClientError> {
    if instruction.program_id != program_id {
        return Ok(None);
    }
    let Some(instruction_tag) = instruction.data.first() else {
        return Ok(None);
    };
    if *instruction_tag != tag::TRANSACT {
        return Ok(None);
    }
    let payload = instruction.data.get(1..).ok_or_else(|| {
        ClientError::Rpc("transact instruction data is missing its payload".into())
    })?;
    let transact_data = TransactIxData::deserialize(payload)
        .map_err(|err| ClientError::Rpc(format!("decode transact instruction data: {err}")))?;
    let mut tags = BTreeSet::new();
    for output in &transact_data.outputs {
        let tag = fetch_tag(
            &output.owner_tag,
            transact_data.p256_signing_pk_x.as_ref(),
            |i| {
                instruction
                    .accounts
                    .get(usize::from(i))
                    .map(|pk| pk.to_bytes())
            },
        )
        .map_err(|err| ClientError::Rpc(format!("resolve output owner tag: {err}")))?;
        tags.insert(tag);
    }
    Ok(Some(tags.into_iter().collect()))
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
        }
    }

    pub fn client(&self) -> &RpcClient {
        &self.client
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
            sleep(Duration::from_millis(250));
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
        instruction_groups_from_confirmed_transaction(signature, transaction)
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
                max_supported_transaction_version: Some(0),
            };
            match self.client.get_transaction_with_config(signature, config) {
                Ok(transaction) => return Ok(transaction),
                Err(_) if started.elapsed() < self.confirmation_timeout => {
                    sleep(Duration::from_millis(250));
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

    pub async fn fetch_confirmed_transaction(
        &self,
        signature: &Signature,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta, ClientError> {
        let started = Instant::now();
        loop {
            let config = RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Json),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
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
        instruction_groups_from_confirmed_transaction(signature, transaction)
    }

    pub async fn transact_output_view_tags_from_signature(
        &self,
        signature: &Signature,
    ) -> Result<Vec<[u8; 32]>, ClientError> {
        let groups = self.fetch_confirmed_instruction_groups(signature).await?;
        transact_output_view_tags_from_instruction_groups(&groups)
    }
}

fn instruction_groups_from_confirmed_transaction(
    signature: &Signature,
    transaction: EncodedConfirmedTransactionWithStatusMeta,
) -> Result<ConfirmedInstructionGroups, ClientError> {
    let encoded = transaction.transaction;
    let meta = encoded
        .meta
        .ok_or_else(|| ClientError::Rpc("transaction missing metadata".into()))?;
    let (account_keys, outer_instructions) =
        transaction_message_parts(encoded.transaction, &meta.loaded_addresses)?;
    let inner = match meta.inner_instructions {
        OptionSerializer::Some(inner) => inner,
        OptionSerializer::None | OptionSerializer::Skip => {
            return Err(ClientError::Rpc(format!(
                "transaction missing inner instructions: {signature}"
            )));
        }
    };

    let mut groups = outer_instructions
        .iter()
        .map(|instruction| parsed_instruction(&account_keys, instruction, Some(1)))
        .map(|outer| {
            outer.map(|outer| InstructionGroup {
                outer,
                inner: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for inner_group in inner {
        let Some(group) = groups.get_mut(inner_group.index as usize) else {
            return Err(ClientError::Rpc(format!(
                "inner instruction group {} has no outer instruction",
                inner_group.index
            )));
        };
        group.inner = inner_group
            .instructions
            .iter()
            .map(|instruction| ui_instruction_to_parsed(&account_keys, instruction))
            .collect::<Result<Vec<_>, _>>()?;
    }

    Ok(ConfirmedInstructionGroups { groups })
}

fn transaction_message_parts(
    transaction: EncodedTransaction,
    loaded_addresses: &OptionSerializer<UiLoadedAddresses>,
) -> Result<(Vec<Pubkey>, Vec<CompiledInstruction>), ClientError> {
    let EncodedTransaction::Json(transaction) = transaction else {
        return Err(ClientError::Rpc("expected JSON-encoded transaction".into()));
    };
    let UiMessage::Raw(message) = transaction.message else {
        return Err(ClientError::Rpc("expected raw transaction message".into()));
    };
    let mut account_keys = message
        .account_keys
        .into_iter()
        .map(parse_pubkey)
        .collect::<Result<Vec<_>, _>>()?;
    if let OptionSerializer::Some(loaded) = loaded_addresses {
        let loaded_keys = loaded
            .writable
            .iter()
            .chain(loaded.readonly.iter())
            .map(parse_pubkey)
            .collect::<Result<Vec<_>, _>>()?;
        account_keys.extend(loaded_keys);
    }
    let instructions = message
        .instructions
        .iter()
        .map(ui_compiled_instruction_to_compiled)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((account_keys, instructions))
}

fn parse_pubkey(key: impl AsRef<str>) -> Result<Pubkey, ClientError> {
    let key = key.as_ref();
    key.parse::<Pubkey>()
        .map_err(|err| ClientError::Rpc(format!("invalid account key {key}: {err}")))
}

fn ui_compiled_instruction_to_compiled(
    instruction: &UiCompiledInstruction,
) -> Result<CompiledInstruction, ClientError> {
    Ok(CompiledInstruction {
        program_id_index: instruction.program_id_index,
        accounts: instruction.accounts.clone(),
        data: bs58::decode(&instruction.data)
            .into_vec()
            .map_err(|err| ClientError::Rpc(format!("invalid instruction data: {err}")))?,
    })
}

fn ui_instruction_to_parsed(
    account_keys: &[Pubkey],
    instruction: &UiInstruction,
) -> Result<ParsedInstruction, ClientError> {
    let UiInstruction::Compiled(instruction) = instruction else {
        return Err(ClientError::Rpc(
            "expected compiled inner instruction".into(),
        ));
    };
    let compiled = ui_compiled_instruction_to_compiled(instruction)?;
    parsed_instruction(account_keys, &compiled, instruction.stack_height)
}

fn parsed_instruction(
    account_keys: &[Pubkey],
    instruction: &CompiledInstruction,
    stack_height: Option<u32>,
) -> Result<ParsedInstruction, ClientError> {
    let program_id = account_keys
        .get(instruction.program_id_index as usize)
        .copied()
        .ok_or_else(|| {
            ClientError::Rpc(format!(
                "program id index {} out of bounds for {} account keys",
                instruction.program_id_index,
                account_keys.len()
            ))
        })?;
    let accounts = instruction
        .accounts
        .iter()
        .map(|index| {
            account_keys.get(*index as usize).copied().ok_or_else(|| {
                ClientError::Rpc(format!(
                    "account index {index} out of bounds for {} account keys",
                    account_keys.len()
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedInstruction::new(
        program_id,
        accounts,
        instruction.data.clone(),
        stack_height,
    ))
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

    fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        self.client
            .send_and_confirm_transaction(transaction)
            .map_err(|err| ClientError::Rpc(format!("send_transaction: {err}")))
    }

    fn send_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: solana_rpc_client_api::config::RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.client
            .send_and_confirm_transaction_with_spinner_and_config(
                transaction,
                CommitmentConfig::confirmed(),
                config,
            )
            .map_err(|err| ClientError::Rpc(format!("send_transaction: {err}")))
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

    async fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        self.client
            .send_and_confirm_transaction(transaction)
            .await
            .map_err(|err| ClientError::Rpc(format!("send_transaction: {err}")))
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &Transaction,
        config: solana_rpc_client_api::config::RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        self.client
            .send_and_confirm_transaction_with_config(
                transaction,
                CommitmentConfig::confirmed(),
                config,
            )
            .await
            .map_err(|err| ClientError::Rpc(format!("send_transaction: {err}")))
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
