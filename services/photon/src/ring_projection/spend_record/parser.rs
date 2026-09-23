use crate::{
    ingester::{
        parser::{rings_event_parser::parse_rings_events, state_update::RingsTransactionUpdate},
        typedefs::block_info::Instruction,
    },
    ring_projection::{instruction_view, Invocation},
};
use anyhow::{Context, Result};
use custom_ring_interface::PolicyConfig;
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, Hash, RingsMessage, RingsOutputContext, RingsOutputSlot, ShieldedTransaction,
};
#[cfg(test)]
pub(crate) use zolana_ring_indexer::spend_record::SuccessorContext;
pub(crate) use zolana_ring_indexer::spend_record::{Rail, Successor};

pub(crate) fn decode(instruction: &Instruction) -> Result<Option<Rail>> {
    zolana_ring_indexer::spend_record::decode(instruction_view(instruction))
}

pub(crate) fn event(invocation: &Invocation<'_>) -> Result<RingsTransactionUpdate> {
    let update = parse_rings_events(&invocation.subtree, invocation.slot)?
        .context("record update has no descendant SPP event")?;
    let [event] = <[RingsTransactionUpdate; 1]>::try_from(update.rings_transactions)
        .map_err(|_| anyhow::anyhow!("record update must have exactly one SPP event"))?;
    Ok(event)
}

pub(crate) struct Reconstruction<'a> {
    pub invocation: &'a Invocation<'a>,
    pub rail: Rail,
    pub event: &'a RingsTransactionUpdate,
    pub policy: &'a PolicyConfig,
}

impl Reconstruction<'_> {
    pub(crate) fn reconstruct(self) -> Result<Successor> {
        let Self {
            invocation,
            rail,
            event,
            policy,
        } = self;
        // The event carries no tree id, the parser pins the output to the entries tree id.
        zolana_ring_indexer::spend_record::Reconstruction {
            instruction: instruction_view(invocation.instruction),
            rail,
            policy,
            event: &ShieldedEvent {
                event,
                program: invocation.instruction.program_id,
                output_tree_id: policy.entries_tree_id(),
            }
            .transaction()?,
            source_instruction_tag: u8::try_from(event.source_instruction_tag)?,
        }
        .reconstruct()
    }
}

#[cfg(test)]
pub(crate) fn successor(
    event: &RingsTransactionUpdate,
    context: &SuccessorContext<'_>,
) -> Result<zolana_ring_policy::SpendRecord> {
    zolana_ring_indexer::spend_record::successor(
        &ShieldedEvent {
            event,
            program: Pubkey::default(),
            output_tree_id: context.entries_tree_id,
        }
        .transaction()?,
        context,
    )
}

struct ShieldedEvent<'a> {
    event: &'a RingsTransactionUpdate,
    program: Pubkey,
    output_tree_id: u16,
}

impl ShieldedEvent<'_> {
    fn transaction(self) -> Result<ShieldedTransaction> {
        let Self {
            event,
            program,
            output_tree_id,
        } = self;
        Ok(ShieldedTransaction {
            slot: event.slot,
            tx_signature: event.signature.into(),
            event_index: Some(u16::try_from(event.event_index)?),
            tx_viewing_pk: event.tx_viewing_pk.clone().map(Base64String),
            salt: event.salt.clone().map(Base64String),
            output_slots: event
                .outputs
                .iter()
                .map(|output| RingsOutputSlot {
                    view_tag: Hash(output.view_tag),
                    output_context: RingsOutputContext {
                        hash: Hash(output.utxo_hash),
                        tree: Pubkey::new_from_array(output.output_tree).into(),
                        tree_id: output_tree_id,
                        leaf_index: output.leaf_index,
                    },
                    payload: Base64String(output.payload.clone()),
                })
                .collect(),
            messages: event
                .messages
                .iter()
                .map(|message| RingsMessage {
                    view_tag: Hash(message.view_tag),
                    payload: Base64String(message.payload.clone()),
                })
                .collect(),
            nullifiers: event
                .nullifiers
                .iter()
                .map(|input| Hash(input.nullifier))
                .collect(),
            proofless: event.proofless,
            ring_config: event
                .ring_config
                .map(|key| Pubkey::new_from_array(key).into()),
            ring_program_id: Some(program.into()),
        })
    }
}
