//! `decode` steps: print the full `transact` instruction data struct and the full
//! emitted event struct (raw `Debug`, no field selection), plus the accounts named
//! by the shared shielded-pool instruction decoder
//! (`zolana_program_test::ZolanaInstructionDecoder`).

use cucumber::then;
use light_instruction_decoder::InstructionDecoder;
use solana_pubkey::Pubkey;
use zolana_event::decode_event_instruction;
use zolana_interface::{
    instruction::{tag, TransactIxData},
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program_test::ZolanaInstructionDecoder;

use crate::LifecycleWorld;

#[then(expr = "the transact instruction data decodes")]
fn transact_decodes(world: &mut LifecycleWorld) {
    let (signature, instruction) = world
        .last_transact
        .clone()
        .expect("a transact instruction was sent");

    let (&tag_byte, payload) = instruction
        .data
        .split_first()
        .expect("instruction has a tag");
    assert_eq!(tag_byte, tag::TRANSACT);
    let data =
        TransactIxData::deserialize(payload).expect("transact instruction data deserializes");

    let decoder = ZolanaInstructionDecoder {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
    };
    let decoded = decoder
        .decode(&instruction.data, &instruction.accounts)
        .expect("transact instruction decodes");
    assert_eq!(decoded.name, "transact");
    assert_eq!(
        decoded.account_names.len(),
        instruction.accounts.len(),
        "decoder must name every account it was sent"
    );

    println!("transaction signature: {signature}");
    println!("instruction data: {data:?}");
    println!("accounts:");
    for (name, meta) in decoded.account_names.iter().zip(&instruction.accounts) {
        println!(
            "  {name} = {} (signer={}, writable={})",
            meta.pubkey, meta.is_signer, meta.is_writable
        );
    }
}

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
