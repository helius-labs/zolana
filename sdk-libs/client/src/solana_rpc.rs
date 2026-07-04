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
    EncodedTransaction, UiCompiledInstruction, UiInstruction, UiLoadedAddresses, UiMessage,
    UiTransactionEncoding,
};
use zolana_event::{InstructionGroup, ParsedInstruction};

use crate::{error::ClientError, rpc::Rpc};

fn pubkey_from_address(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

pub struct SolanaRpc {
    client: RpcClient,
    confirmation_timeout: Duration,
    /// Answers the SPP indexer methods (spend proofs). Set it with
    /// [`SolanaRpc::with_indexer`] so one backend both fetches proofs and sends
    /// transactions, which is what [`Submit::execute`](crate::Submit::execute)
    /// and the other one-call actions need.
    #[cfg(feature = "indexer-api")]
    indexer: Option<crate::indexer::ZolanaIndexer>,
}

#[derive(Clone, Debug)]
pub struct ConfirmedInstructionGroups {
    pub groups: Vec<InstructionGroup>,
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
            #[cfg(feature = "indexer-api")]
            indexer: None,
        }
    }

    /// Attach an indexer so this backend also answers spend-proof lookups. With
    /// it set, a single `SolanaRpc` satisfies the one-call actions
    /// ([`Submit::execute`](crate::Submit::execute)) that both fetch proofs and
    /// send the transaction.
    #[cfg(feature = "indexer-api")]
    pub fn with_indexer(mut self, indexer: crate::indexer::ZolanaIndexer) -> Self {
        self.indexer = Some(indexer);
        self
    }

    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    /// The attached indexer, or `UnsupportedRpcMethod` if none was set. The
    /// message name matches the caller so the error still reads as "this
    /// backend can't do X".
    #[cfg(feature = "indexer-api")]
    fn indexer(&self) -> Result<&crate::indexer::ZolanaIndexer, ClientError> {
        self.indexer
            .as_ref()
            .ok_or(ClientError::UnsupportedRpcMethod(
                "get_merkle_proofs (no indexer attached; use SolanaRpc::with_indexer)",
            ))
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

    // ===== Indexer (SPP) =====
    //
    // Delegated to the attached indexer. Without one, these keep the trait's
    // default behavior: `ClientError::UnsupportedRpcMethod`.

    #[cfg(feature = "indexer-api")]
    fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<crate::rpc::GetEncryptedUtxosByTagsResponse, ClientError> {
        self.indexer()?
            .get_encrypted_utxos_by_tags(tags, cursor, limit)
    }

    #[cfg(feature = "indexer-api")]
    fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<crate::rpc::GetShieldedTransactionsByTagsResponse, ClientError> {
        self.indexer()?
            .get_shielded_transactions_by_tags(tags, cursor, limit)
    }

    #[cfg(feature = "indexer-api")]
    fn subscribe_to_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
    ) -> Result<crate::rpc::ShieldedTransactionStream, ClientError> {
        self.indexer()?
            .subscribe_to_shielded_transactions_by_tags(tags)
    }

    #[cfg(feature = "indexer-api")]
    fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<crate::rpc::GetMerkleProofsResponse, ClientError> {
        self.indexer()?.get_merkle_proofs(tree_account, leaves)
    }

    #[cfg(feature = "indexer-api")]
    fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
    ) -> Result<crate::rpc::GetNonInclusionProofsResponse, ClientError> {
        self.indexer()?
            .get_non_inclusion_proofs(tree_account, leaves)
    }
}
