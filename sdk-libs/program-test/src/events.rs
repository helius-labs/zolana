use litesvm::types::TransactionMetadata;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_pubkey::Pubkey;
use zolana_event::{indexed_events_from_instruction_groups, proofless_output, ProoflessOutput};
pub use zolana_event::{IndexedEvent, InstructionGroup, ParsedInstruction};

use crate::{ProgramTestError, TestIndexer};

/// A proofless deposit reconstructed from a `GeneralEvent`: the borsh
/// [`ProoflessOutput`] body plus the output-slot context (view tag, UTXO hash,
/// tree, leaf index) the event carries alongside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositOutput {
    pub view_tag: [u8; 32],
    pub utxo_hash: [u8; 32],
    pub output_tree: [u8; 32],
    pub leaf_index: u64,
    pub output: ProoflessOutput,
}

impl DepositOutput {
    /// Wraps the deposit into a proofless [`ShieldedTransaction`] whose single
    /// output slot carries the encoded [`ProoflessOutput`] payload, so a wallet
    /// can rediscover it via `Wallet::sync`.
    pub fn to_shielded_transaction(
        &self,
        tx_signature: solana_signature::Signature,
    ) -> zolana_transaction::ShieldedTransaction {
        zolana_transaction::ShieldedTransaction {
            slot: 0,
            tx_signature,
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![zolana_transaction::OutputSlot {
                view_tag: self.view_tag,
                output_context: zolana_transaction::OutputContext {
                    hash: self.utxo_hash,
                    tree: zolana_transaction::Address::new_from_array(self.output_tree),
                    leaf_index: self.leaf_index,
                },
                payload: zolana_event::encode_output_data(self.output.clone()),
            }],
            messages: Vec::new(),
            nullifiers: Vec::new(),
            proofless: true,
        }
    }
}

pub fn parsed_instruction_from_compiled(
    account_keys: &[Pubkey],
    instruction: &CompiledInstruction,
    stack_height: Option<u32>,
) -> Result<ParsedInstruction, ProgramTestError> {
    let program_id = account_keys
        .get(instruction.program_id_index as usize)
        .copied()
        .ok_or_else(|| {
            ProgramTestError::Event(format!(
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
                ProgramTestError::Event(format!(
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

pub fn parsed_instruction_groups_from_meta(
    account_keys: &[Pubkey],
    outer_instructions: &[CompiledInstruction],
    meta: &TransactionMetadata,
) -> Result<Vec<InstructionGroup>, ProgramTestError> {
    let mut groups = outer_instructions
        .iter()
        .map(|instruction| {
            parsed_instruction_from_compiled(account_keys, instruction, Some(1)).map(|outer| {
                InstructionGroup {
                    outer,
                    inner: Vec::new(),
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (outer_index, inner_instructions) in meta.inner_instructions.iter().enumerate() {
        let Some(group) = groups.get_mut(outer_index) else {
            return Err(ProgramTestError::Event(format!(
                "inner instruction group {outer_index} has no outer instruction"
            )));
        };
        group.inner = inner_instructions
            .iter()
            .map(|inner| {
                parsed_instruction_from_compiled(
                    account_keys,
                    &inner.instruction,
                    Some(u32::from(inner.stack_height)),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
    }

    Ok(groups)
}

pub fn indexed_events_from_meta(
    shielded_pool_program_id: Pubkey,
    account_keys: &[Pubkey],
    outer_instructions: &[CompiledInstruction],
    meta: &TransactionMetadata,
) -> Result<Vec<IndexedEvent>, ProgramTestError> {
    let groups = parsed_instruction_groups_from_meta(account_keys, outer_instructions, meta)?;
    Ok(indexed_events_from_instruction_groups(
        shielded_pool_program_id,
        &groups,
    ))
}

pub fn deposit_output_from_event(event: &IndexedEvent) -> Result<DepositOutput, ProgramTestError> {
    let general_event = match &event.decoded {
        Ok(general_event) => general_event,
        Err(err) => {
            return Err(ProgramTestError::Event(format!(
                "invalid shielded-pool event tag={} payload_len={} error={err:?}",
                event.tag,
                event.payload.len()
            )));
        }
    };
    let output = proofless_output(general_event).map_err(|err| {
        ProgramTestError::Event(format!(
            "invalid proofless output tag={} payload_len={} error={err:?}",
            event.tag,
            event.payload.len()
        ))
    })?;
    let slot = general_event.outputs.first().ok_or_else(|| {
        ProgramTestError::Event("proofless deposit event has no output slot".into())
    })?;
    Ok(DepositOutput {
        view_tag: slot.view_tag,
        utxo_hash: slot.utxo_hash,
        output_tree: general_event.output_tree,
        leaf_index: general_event.first_output_leaf_index,
        output,
    })
}

pub fn index_events(
    indexer: &mut TestIndexer,
    events: &[IndexedEvent],
) -> Result<(), ProgramTestError> {
    for event in events {
        let deposit = deposit_output_from_event(event)?;
        indexer.record_deposit(&deposit)?;
    }
    Ok(())
}

pub fn single_deposit_view(events: &[IndexedEvent]) -> Result<DepositOutput, ProgramTestError> {
    let mut deposits = events.iter().map(deposit_output_from_event);
    let Some(deposit) = deposits.next() else {
        return Err(ProgramTestError::Event(
            "no proofless deposit event emitted by transaction".into(),
        ));
    };
    let deposit = deposit?;
    if deposits.next().transpose()?.is_some() {
        return Err(ProgramTestError::Event(
            "expected one proofless deposit view".into(),
        ));
    }
    Ok(deposit)
}
