use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
#[cfg(feature = "solana-rpc")]
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
#[cfg(feature = "solana-rpc")]
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
#[cfg(feature = "solana-rpc")]
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedTransaction, UiInstruction, UiLoadedAddresses,
    UiMessage, UiTransactionEncoding,
};
use zolana_client::{ClientError, Rpc};
#[cfg(feature = "solana-rpc")]
use zolana_client::SolanaRpc;
#[cfg(feature = "solana-rpc")]
use zolana_interface::instruction::tag;

#[cfg(feature = "solana-rpc")]
use crate::events::indexed_events_from_instructions;
#[cfg(feature = "solana-rpc")]
use crate::PoolIndexer;
use crate::{
    events::{index_events, indexed_events_from_meta, IndexedEvent},
    logging::{log_failed_transaction, log_transaction},
    ProgramTestError, ZolanaProgramTest,
};

#[derive(Debug)]
pub struct IndexedTransaction {
    pub signature: Signature,
    pub events: Vec<IndexedEvent>,
}

impl ZolanaProgramTest {
    /// Build, sign, send, and index a transaction against the litesvm backend.
    pub fn create_and_send_transaction(
        &mut self,
        ixs: &[Instruction],
        payer: &Pubkey,
        signers: &[&Keypair],
    ) -> Result<IndexedTransaction, ProgramTestError> {
        let blockhash = self.svm.latest_blockhash();
        let message = Message::new(ixs, Some(payer));
        let transaction = Transaction::new(signers, message, blockhash);
        self.send_indexed(transaction)
    }

    fn send_indexed(
        &mut self,
        transaction: Transaction,
    ) -> Result<IndexedTransaction, ProgramTestError> {
        let signature = transaction
            .signatures
            .first()
            .copied()
            .ok_or_else(|| ProgramTestError::Rpc("transaction has no signatures".into()))?;
        let message = transaction.message.clone();
        let slot = self.svm.get_sysvar::<Clock>().slot;
        let meta = match self.svm.send_transaction(transaction) {
            Ok(meta) => meta,
            Err(err) => {
                log_failed_transaction(self.program_id, slot, &message, &err);
                return Err(ProgramTestError::Litesvm(format!(
                    "send_transaction: {err:?}"
                )));
            }
        };
        let events = indexed_events_from_meta(self.program_id, &message.account_keys, &meta)?;
        index_events(&mut self.indexer, &events)?;
        log_transaction(self.program_id, slot, &message, &meta, &events);
        Ok(IndexedTransaction { signature, events })
    }
}

impl Rpc for ZolanaProgramTest {
    fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let pubkey = Pubkey::new_from_array(address.to_bytes());
        Ok(self.svm.get_account(&pubkey))
    }

    fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
    ) -> Result<u64, ClientError> {
        Ok(self.svm.minimum_balance_for_rent_exemption(data_len))
    }

    fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((self.svm.latest_blockhash(), 0))
    }
}

/// Send a transaction to a live validator via [`SolanaRpc`] and, when it carries
/// shielded events, fetch and index them into the supplied [`PoolIndexer`].
#[cfg(feature = "solana-rpc")]
pub fn send_and_index(
    rpc: &mut SolanaRpc,
    indexer: &mut PoolIndexer,
    shielded_pool_program_id: Pubkey,
    transaction: Transaction,
) -> Result<IndexedTransaction, ProgramTestError> {
    let produces_events =
        produces_shielded_events(shielded_pool_program_id, &transaction.message);
    let signature = rpc
        .client()
        .send_and_confirm_transaction(&transaction)
        .map_err(|err| ProgramTestError::Rpc(format!("send_transaction: {err}")))?;
    let events = if produces_events {
        fetch_indexed_events(rpc, indexer, shielded_pool_program_id, &signature)?
    } else {
        Vec::new()
    };
    Ok(IndexedTransaction { signature, events })
}

#[cfg(feature = "solana-rpc")]
fn fetch_indexed_events(
    rpc: &SolanaRpc,
    indexer: &mut PoolIndexer,
    shielded_pool_program_id: Pubkey,
    signature: &Signature,
) -> Result<Vec<IndexedEvent>, ProgramTestError> {
    use std::{thread::sleep, time::{Duration, Instant}};

    use solana_rpc_client::api::config::RpcTransactionConfig;

    let confirmation_timeout = Duration::from_secs(30);
    let started = Instant::now();
    let transaction = loop {
        let config = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };
        match rpc.client().get_transaction_with_config(signature, config) {
            Ok(transaction) => break transaction,
            Err(_) if started.elapsed() < confirmation_timeout => {
                sleep(Duration::from_millis(250));
            }
            Err(err) => {
                return Err(ProgramTestError::Rpc(format!(
                    "get_transaction {signature}: {err}"
                )));
            }
        }
    };
    let encoded = transaction.transaction;
    let meta = encoded
        .meta
        .ok_or_else(|| ProgramTestError::Rpc("transaction missing metadata".into()))?;
    let account_keys = account_keys_from_transaction(encoded.transaction, &meta.loaded_addresses)?;
    let inner = match meta.inner_instructions {
        OptionSerializer::Some(inner) => inner,
        OptionSerializer::None | OptionSerializer::Skip => {
            return Err(ProgramTestError::Rpc(format!(
                "transaction missing inner instructions: {signature}"
            )));
        }
    };
    let instructions = inner
        .iter()
        .flat_map(|inner| inner.instructions.iter())
        .map(|instruction| parsed_instruction_from_ui(instruction, &account_keys))
        .collect::<Result<Vec<_>, _>>()?;
    let events = indexed_events_from_instructions(shielded_pool_program_id, &instructions)?;
    index_events(indexer, &events)?;
    Ok(events)
}

#[cfg(feature = "solana-rpc")]
fn produces_shielded_events(shielded_pool_program_id: Pubkey, message: &Message) -> bool {
    message.instructions.iter().any(|instruction| {
        let Some(ix_tag) = instruction.data.first().copied() else {
            return false;
        };
        match ix_tag {
            tag::PROOFLESS_SHIELD => {
                instruction_program_id(message, instruction) == Some(shielded_pool_program_id)
            }
            tag::ZONE_PROOFLESS_SHIELD => {
                instruction_program_id(message, instruction) == Some(shielded_pool_program_id)
                    || instruction.accounts.iter().any(|index| {
                        message.account_keys.get(*index as usize) == Some(&shielded_pool_program_id)
                    })
            }
            _ => false,
        }
    })
}

#[cfg(feature = "solana-rpc")]
fn instruction_program_id(message: &Message, instruction: &CompiledInstruction) -> Option<Pubkey> {
    message
        .account_keys
        .get(instruction.program_id_index as usize)
        .copied()
}

#[cfg(feature = "solana-rpc")]
fn account_keys_from_transaction(
    transaction: EncodedTransaction,
    loaded_addresses: &OptionSerializer<UiLoadedAddresses>,
) -> Result<Vec<Pubkey>, ProgramTestError> {
    let EncodedTransaction::Json(transaction) = transaction else {
        return Err(ProgramTestError::Rpc(
            "expected JSON-encoded transaction".into(),
        ));
    };
    let UiMessage::Raw(message) = transaction.message else {
        return Err(ProgramTestError::Rpc(
            "expected raw transaction message".into(),
        ));
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

#[cfg(feature = "solana-rpc")]
fn parse_pubkey(key: impl AsRef<str>) -> Result<Pubkey, ProgramTestError> {
    let key = key.as_ref();
    key.parse::<Pubkey>()
        .map_err(|err| ProgramTestError::Rpc(format!("invalid account key {key}: {err}")))
}

#[cfg(feature = "solana-rpc")]
fn parsed_instruction_from_ui(
    instruction: &UiInstruction,
    account_keys: &[Pubkey],
) -> Result<crate::ParsedInstruction, ProgramTestError> {
    let UiInstruction::Compiled(instruction) = instruction else {
        return Err(ProgramTestError::Rpc(
            "expected compiled inner instruction".into(),
        ));
    };
    let program_id = account_keys
        .get(instruction.program_id_index as usize)
        .copied()
        .ok_or_else(|| {
            ProgramTestError::Rpc("inner instruction program id index out of bounds".into())
        })?;
    let accounts = instruction
        .accounts
        .iter()
        .map(|index| {
            account_keys.get(*index as usize).copied().ok_or_else(|| {
                ProgramTestError::Rpc(format!(
                    "inner instruction account index {index} out of bounds"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::ParsedInstruction {
        program_id,
        accounts,
        data: bs58::decode(&instruction.data)
            .into_vec()
            .map_err(|err| ProgramTestError::Rpc(format!("invalid instruction data: {err}")))?,
    })
}

#[cfg(all(test, feature = "solana-rpc"))]
mod tests {
    use super::*;
    use solana_instruction::{AccountMeta, Instruction};

    #[test]
    fn shielded_event_detection_checks_program_context() {
        let shielded_pool = Pubkey::new_unique();
        let other_program = Pubkey::new_unique();

        let unrelated = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: Vec::new(),
                data: vec![tag::PROOFLESS_SHIELD],
            }],
            None,
        );
        assert!(!produces_shielded_events(shielded_pool, &unrelated));

        let direct = Message::new(
            &[Instruction {
                program_id: shielded_pool,
                accounts: Vec::new(),
                data: vec![tag::PROOFLESS_SHIELD],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &direct));

        let zone_wrapper = Message::new(
            &[Instruction {
                program_id: other_program,
                accounts: vec![AccountMeta::new_readonly(shielded_pool, false)],
                data: vec![tag::ZONE_PROOFLESS_SHIELD],
            }],
            None,
        );
        assert!(produces_shielded_events(shielded_pool, &zone_wrapper));
    }
}
