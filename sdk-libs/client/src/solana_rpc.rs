//! Generic blocking Solana RPC backend.
//!
//! Wraps a `solana_rpc_client::RpcClient` and implements [`Rpc`] over
//! it. It can expose confirmed instruction groups for event parsers, but it
//! does not index shielded-pool state itself.

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use solana_rpc_client::{api::config::RpcTransactionConfig, rpc_client::RpcClient};
use solana_signature::Signature;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    EncodedTransaction, TransactionConfirmationStatus, UiCompiledInstruction, UiInstruction,
    UiLoadedAddresses, UiMessage, UiTransactionEncoding,
};
use zolana_event::{InstructionGroup, ParsedInstruction};

use crate::{error::ClientError, rpc::Rpc};

fn pubkey_from_address(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

pub struct SolanaRpc {
    client: RpcClient,
    confirmation_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ConfirmedInstructionGroups {
    pub groups: Vec<InstructionGroup>,
}

/// On-chain outcome of a submitted signature, as seen by the RPC.
///
/// Distinguishes a genuine on-chain failure (surface immediately), a signature
/// that has landed but is not yet confirmed ([`SignatureState::Pending`]), a
/// wholly not-yet-visible signature ([`SignatureState::NotFound`]), and a
/// confirmed success. A confirmed transaction is a successful one even if a
/// downstream indexer has not caught up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureState {
    /// The transaction landed but executed with an error.
    Failed(String),
    /// The transaction is confirmed (or finalized) with no execution error.
    Confirmed,
    /// The transaction has landed and is `Processed` but not yet confirmed. It is
    /// on-chain, so callers must NOT resubmit it; keep polling for confirmation.
    Pending,
    /// The RPC has no record of the signature at all (still propagating, or
    /// dropped). Unlike [`SignatureState::Pending`], nothing has landed.
    NotFound,
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

    /// Classify a submitted signature via `getSignatureStatuses`
    /// (`searchTransactionHistory = true`), so the wait path can fail fast on a
    /// genuine on-chain failure and treat confirmed-but-unindexed as success.
    /// A `Processed`-but-unconfirmed signature is [`SignatureState::Pending`] (it
    /// has landed); a wholly missing status is [`SignatureState::NotFound`] (still
    /// propagating). Neither is an error.
    pub fn signature_state(&self, signature: &Signature) -> Result<SignatureState, ClientError> {
        let statuses = self
            .client
            .get_signature_statuses_with_history(&[*signature])
            .map_err(|err| ClientError::Rpc(format!("get_signature_statuses {signature}: {err}")))?
            .value;
        match statuses.into_iter().next().flatten() {
            Some(status) => match status.err {
                Some(err) => Ok(SignatureState::Failed(err.to_string())),
                None => match status.confirmation_status() {
                    TransactionConfirmationStatus::Confirmed
                    | TransactionConfirmationStatus::Finalized => Ok(SignatureState::Confirmed),
                    TransactionConfirmationStatus::Processed => Ok(SignatureState::Pending),
                },
            },
            None => Ok(SignatureState::NotFound),
        }
    }

    pub fn fetch_confirmed_instruction_groups(
        &self,
        signature: &Signature,
    ) -> Result<ConfirmedInstructionGroups, ClientError> {
        let transaction = self.fetch_confirmed_transaction(signature)?;
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

    /// Fetch a confirmed transaction and serialize it to the same pretty JSON
    /// shape the RPC `getTransaction` (encoding `json`) call returns. Used to
    /// capture indexer test fixtures.
    pub fn fetch_confirmed_transaction_json(
        &self,
        signature: &Signature,
    ) -> Result<String, ClientError> {
        let transaction = self.fetch_confirmed_transaction(signature)?;
        serde_json::to_string_pretty(&transaction)
            .map_err(|err| ClientError::Rpc(format!("serialize transaction {signature}: {err}")))
    }

    /// Slot the given confirmed transaction landed in.
    pub fn fetch_confirmed_transaction_slot(
        &self,
        signature: &Signature,
    ) -> Result<u64, ClientError> {
        Ok(self.fetch_confirmed_transaction(signature)?.slot)
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
        let blockhash = self
            .client
            .get_latest_blockhash()
            .map_err(|err| ClientError::Rpc(format!("get_latest_blockhash: {err}")))?;
        Ok((blockhash, 0))
    }

    fn send_transaction(&self, transaction: &Transaction) -> Result<Signature, ClientError> {
        self.client
            .send_and_confirm_transaction(transaction)
            .map_err(|err| ClientError::Rpc(format!("send_transaction: {err}")))
    }
}
