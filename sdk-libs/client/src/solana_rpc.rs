//! Generic blocking Solana RPC backend.
//!
//! Wraps a `solana_rpc_client::RpcClient` and implements [`Rpc`] over
//! it. This backend carries no shielded-pool indexing knowledge; callers that
//! need indexed events build that on top using the raw client.

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
use solana_rpc_client::api::config::RpcTransactionConfig;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    EncodedTransaction, UiInstruction, UiLoadedAddresses, UiMessage, UiTransactionEncoding,
};

use crate::error::ClientError;
use crate::rpc::Rpc;

fn pubkey_from_address(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

pub struct SolanaRpc {
    client: RpcClient,
    confirmation_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ConfirmedInnerInstructions {
    pub account_keys: Vec<Pubkey>,
    pub instructions: Vec<CompiledInstruction>,
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

    pub fn fetch_confirmed_inner_instructions(
        &self,
        signature: &Signature,
    ) -> Result<ConfirmedInnerInstructions, ClientError> {
        let transaction = self.fetch_confirmed_transaction(signature)?;
        let encoded = transaction.transaction;
        let meta = encoded
            .meta
            .ok_or_else(|| ClientError::Rpc("transaction missing metadata".into()))?;
        let account_keys =
            account_keys_from_transaction(encoded.transaction, &meta.loaded_addresses)?;
        let inner = match meta.inner_instructions {
            OptionSerializer::Some(inner) => inner,
            OptionSerializer::None | OptionSerializer::Skip => {
                return Err(ClientError::Rpc(format!(
                    "transaction missing inner instructions: {signature}"
                )));
            }
        };
        let instructions = inner
            .iter()
            .flat_map(|inner| inner.instructions.iter())
            .map(ui_instruction_to_compiled)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ConfirmedInnerInstructions {
            account_keys,
            instructions,
        })
    }

    fn fetch_confirmed_transaction(
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

fn account_keys_from_transaction(
    transaction: EncodedTransaction,
    loaded_addresses: &OptionSerializer<UiLoadedAddresses>,
) -> Result<Vec<Pubkey>, ClientError> {
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
    Ok(account_keys)
}

fn parse_pubkey(key: impl AsRef<str>) -> Result<Pubkey, ClientError> {
    let key = key.as_ref();
    key.parse::<Pubkey>()
        .map_err(|err| ClientError::Rpc(format!("invalid account key {key}: {err}")))
}

fn ui_instruction_to_compiled(
    instruction: &UiInstruction,
) -> Result<CompiledInstruction, ClientError> {
    let UiInstruction::Compiled(instruction) = instruction else {
        return Err(ClientError::Rpc(
            "expected compiled inner instruction".into(),
        ));
    };
    Ok(CompiledInstruction {
        program_id_index: instruction.program_id_index,
        accounts: instruction.accounts.clone(),
        data: bs58::decode(&instruction.data)
            .into_vec()
            .map_err(|err| ClientError::Rpc(format!("invalid instruction data: {err}")))?,
    })
}

impl Rpc for SolanaRpc {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let pubkey = pubkey_from_address(&address);
        match self.client.get_account(&pubkey) {
            Ok(account) => Ok(Some(account)),
            Err(err) => Err(ClientError::Rpc(format!("get_account {pubkey}: {err}"))),
        }
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
