//! `decode` step: parse the `GeneralEvent` a `transact` logged and print the full
//! event struct (raw `Debug`, no field selection) so a reader can inspect what was
//! emitted on chain.

use cucumber::then;
use rings_event::decode_event_instruction;
use rings_interface::{instruction::tag, SHIELDED_POOL_PROGRAM_ID};
use solana_pubkey::Pubkey;

use crate::LifecycleWorld;

/// Parse the `GeneralEvent` the `transact` logged. The program emits it through an
/// `emit_event` self-CPI, so it is an inner instruction of the transaction.
#[then(expr = "the emitted event decodes")]
fn event_decodes(world: &mut LifecycleWorld) {
    let (signature, _) = world
        .last_transact
        .clone()
        .expect("a transact instruction was sent");
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

    let groups = world
        .rpc
        .fetch_confirmed_instruction_groups(&signature)
        .expect("fetch confirmed instruction groups");
    let emit_event = groups
        .groups
        .iter()
        .flat_map(|group| &group.inner)
        .find(|ix| ix.program_id == program_id && ix.data.first() == Some(&tag::EMIT_EVENT))
        .expect("transact emitted an event via the emit_event self-CPI");

    let event = decode_event_instruction(&emit_event.data).expect("emit_event payload decodes");

    println!("event: {event:?}");
}
