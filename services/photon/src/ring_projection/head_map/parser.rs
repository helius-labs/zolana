use crate::{
    ingester::{
        parser::{rings_event_parser::parse_rings_events, state_update::RingsTransactionUpdate},
        typedefs::block_info::Instruction,
    },
    ring_projection::{fault, instruction_view, BlockEnv, Invocation, ProjectError},
};
use anyhow::{bail, Context, Result};
use custom_ring_interface::PolicyConfig;
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, Hash, RingsMessage, RingsOutputContext, RingsOutputSlot, ShieldedTransaction,
};
pub(crate) use zolana_ring_indexer::head_map::parser::{Decoded, Transfer, Transition};
#[cfg(test)]
pub(crate) use zolana_ring_indexer::head_map::parser::{Rail, Registration, SuccessorContext};

pub(super) async fn transition(
    invocation: &Invocation<'_>,
    env: &mut BlockEnv<'_>,
) -> Result<Option<Transition>, ProjectError> {
    let Some(decoded) = decode(invocation.instruction).map_err(invalid)? else {
        return Ok(None);
    };
    let policy = env.policy(&invocation.instruction.program_id).await?;
    reconstruct(invocation, decoded, &policy)
        .map(Some)
        .map_err(invalid)
}

fn invalid(error: anyhow::Error) -> ProjectError {
    fault(format!("{error:#}"))
}

pub(crate) fn decode(instruction: &Instruction) -> Result<Option<Decoded>> {
    zolana_ring_indexer::head_map::parser::decode(instruction_view(instruction))
}

pub(crate) fn reconstruct(
    invocation: &Invocation<'_>,
    decoded: Decoded,
    policy: &PolicyConfig,
) -> Result<Transition> {
    let update = parse_rings_events(&invocation.subtree, invocation.slot)?
        .context("transition has no descendant SPP event")?;
    if update.rings_transactions.len() != 1 {
        bail!("transition must have exactly one SPP event");
    }
    let event = &update.rings_transactions[0];
    zolana_ring_indexer::head_map::parser::Reconstruction {
        instruction: instruction_view(invocation.instruction),
        decoded,
        policy,
        event: &transaction(event, invocation.instruction.program_id)?,
        source_instruction_tag: u8::try_from(event.source_instruction_tag)?,
    }
    .reconstruct()
}

#[cfg(test)]
pub(crate) fn successor(
    event: &RingsTransactionUpdate,
    context: &SuccessorContext<'_>,
) -> Result<zolana_ring_policy::SpendRecord> {
    zolana_ring_indexer::head_map::parser::successor(
        &transaction(event, Pubkey::default())?,
        context,
    )
}

fn transaction(event: &RingsTransactionUpdate, program: Pubkey) -> Result<ShieldedTransaction> {
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
