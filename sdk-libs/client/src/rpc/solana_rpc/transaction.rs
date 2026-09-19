use std::collections::BTreeSet;

use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    EncodedTransaction, UiCompiledInstruction, UiInstruction, UiLoadedAddresses, UiMessage,
};
use zolana_event_parser::{InstructionGroup, ParsedInstruction};
use zolana_interface::{
    instruction::{
        instruction_data::transact::{fetch_tag, TransactIxData},
        tag,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

use crate::error::ClientError;

#[derive(Clone, Debug)]
pub struct ConfirmedInstructionGroups {
    pub groups: Vec<InstructionGroup>,
}

impl TryFrom<EncodedConfirmedTransactionWithStatusMeta> for ConfirmedInstructionGroups {
    type Error = ClientError;

    fn try_from(
        transaction: EncodedConfirmedTransactionWithStatusMeta,
    ) -> Result<Self, Self::Error> {
        instruction_groups_from_confirmed_transaction(transaction)
    }
}

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
        let tag = fetch_tag(&output.owner_tag, |i| {
            instruction
                .accounts
                .get(usize::from(i))
                .map(|pk| pk.to_bytes())
        })
        .map_err(|err| ClientError::Rpc(format!("resolve output owner tag: {err}")))?;
        tags.insert(tag);
    }
    Ok(Some(tags.into_iter().collect()))
}

pub(super) fn instruction_groups_from_confirmed_transaction(
    transaction: EncodedConfirmedTransactionWithStatusMeta,
) -> Result<ConfirmedInstructionGroups, ClientError> {
    let encoded = transaction.transaction;
    let meta = encoded
        .meta
        .ok_or_else(|| ClientError::Rpc("transaction missing metadata".into()))?;
    if let Some(err) = &meta.err {
        return Err(ClientError::TransactionFailed(err.to_string()));
    }
    let (account_keys, outer_instructions) =
        transaction_message_parts(encoded.transaction, &meta.loaded_addresses)?;
    let inner = match meta.inner_instructions {
        OptionSerializer::Some(inner) => inner,
        OptionSerializer::None | OptionSerializer::Skip => {
            return Err(ClientError::Rpc(
                "transaction missing inner instructions".to_string(),
            ));
        }
    };

    let mut groups = outer_instructions
        .iter()
        .map(|instruction| parsed_instruction(&account_keys, instruction, 1))
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

/// Resolve a confirmed transaction's account keys and outer instructions.
///
/// This client only sends v1, which loads no addresses, so `loaded_addresses`
/// is always absent for its own transactions. It is still honoured because this
/// decodes transactions off the chain rather than ones it just built: every
/// shielded transaction confirmed before the move to v1 is a v0 one whose
/// compiled instruction indexes only resolve once the looked-up keys are
/// appended. Dropping this would not simplify anything, it would stop the
/// client reading its own history.
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
    let stack_height = instruction
        .stack_height
        .ok_or_else(|| ClientError::Rpc("inner instruction missing stack height".into()))?;
    parsed_instruction(account_keys, &compiled, stack_height)
}

fn parsed_instruction(
    account_keys: &[Pubkey],
    instruction: &CompiledInstruction,
    stack_height: u32,
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
