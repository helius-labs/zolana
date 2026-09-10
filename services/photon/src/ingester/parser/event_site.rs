//! Photon-side glue for the event-site discovery in `zolana_event`.
//!
//! The shielded pool emits events by re-invoking itself with an `EMIT_EVENT`
//! instruction, so an event is an inner instruction and its payload is
//! attacker-reachable. `zolana_event::find_event_sites` only accepts an event
//! whose parent is a genuine state-transitioning instruction of the pool, and
//! every Photon event parser must go through it. This module converts Photon's
//! transaction shape into the event crate's and reads the ring identity off an
//! accepted parent.

use crate::ingester::typedefs::block_info::{
    Instruction as PhotonInstruction, InstructionGroup as PhotonInstructionGroup,
};
use solana_pubkey::Pubkey;
use zolana_event::{EventSite, InstructionGroup, ParsedInstruction};
use zolana_interface::instruction::InstructionTag;

pub fn to_rings_instruction_groups(groups: &[PhotonInstructionGroup]) -> Vec<InstructionGroup> {
    let to_rings_instruction = |instruction: &PhotonInstruction| {
        ParsedInstruction::new(
            instruction.program_id,
            instruction.accounts.clone(),
            instruction.data.clone(),
            instruction.stack_height,
        )
    };

    groups
        .iter()
        .map(|group| InstructionGroup {
            outer: to_rings_instruction(&group.outer_instruction),
            inner: group
                .inner_instructions
                .iter()
                .map(to_rings_instruction)
                .collect(),
        })
        .collect()
}

/// The ring's `ring_auth` PDA for a ring instruction, `None` for an instruction
/// without a ring or one whose account list is too short to hold it.
pub fn ring_config(site: &EventSite<'_>) -> Option<Pubkey> {
    ring_config_index(site.source_instruction_tag)
        .and_then(|index| site.parent.accounts.get(index).copied())
}

/// Position of the signed `ring_config` account in each ring instruction, or
/// `None` when the instruction has no ring.
///
/// The pool reads the ring's identity from this account, never from the caller:
/// the ring signs with its `ring_auth` PDA, but a router between the ring and
/// the pool would leave the outer program something else entirely. Positions
/// come from the account iterators in `transact/account.rs`,
/// `deposit/account.rs`, and `merge_ring/account.rs`.
fn ring_config_index(source_instruction_tag: u8) -> Option<usize> {
    match InstructionTag::try_from(source_instruction_tag).ok()? {
        // payer, input_tree, output_tree, pool, system_program, ring_config
        InstructionTag::RingTransact | InstructionTag::RingAuthorityTransact => Some(5),
        // tree, depositor, ring_config
        InstructionTag::RingDeposit => Some(2),
        // input_tree, output_tree, ring_config
        InstructionTag::RingMergeTransact => Some(2),
        _ => None,
    }
}
