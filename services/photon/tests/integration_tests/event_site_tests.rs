//! Reading the ring identity off an accepted event site.

use photon_indexer::ingester::{
    parser::event_site::{ring_config, to_rings_instruction_groups},
    typedefs::block_info::{Instruction, InstructionGroup},
};
use solana_pubkey::Pubkey;
use zolana_event::{find_event_sites, ParsedInstruction};
use zolana_interface::{instruction::tag, pda};

fn spp() -> Pubkey {
    pda::shielded_pool_program_id()
}

fn foreign() -> Pubkey {
    Pubkey::new_from_array([9; 32])
}

fn ix(program_id: Pubkey, tag_byte: u8, accounts: Vec<Pubkey>, stack_height: u32) -> Instruction {
    Instruction {
        program_id,
        accounts,
        data: vec![tag_byte, 1, 2, 3],
        stack_height: Some(stack_height),
    }
}

fn numbered_accounts(count: u8) -> Vec<Pubkey> {
    (0..count)
        .map(|i| Pubkey::new_from_array([i; 32]))
        .collect()
}

/// Ring rail shape: a foreign ring program on top, the pool instruction and its
/// event underneath.
fn ring_config_of(source_tag: u8, accounts: Vec<Pubkey>) -> Option<Pubkey> {
    let photon_groups = [InstructionGroup {
        outer_instruction: ix(foreign(), 0, Vec::new(), 1),
        inner_instructions: vec![
            ix(spp(), source_tag, accounts, 2),
            ix(spp(), tag::EMIT_EVENT, Vec::new(), 3),
        ],
    }];
    let groups = to_rings_instruction_groups(&photon_groups);
    let sites = find_event_sites(spp(), &groups, |source| source == source_tag);
    let site = sites.first().expect("one event site");
    ring_config(site)
}

#[test]
fn photon_instruction_groups_convert_field_for_field() {
    let photon_groups = [InstructionGroup {
        outer_instruction: ix(foreign(), 7, numbered_accounts(2), 1),
        inner_instructions: vec![ix(spp(), tag::TRANSACT, numbered_accounts(3), 2)],
    }];

    let groups = to_rings_instruction_groups(&photon_groups);

    let group = groups.first().expect("one group");
    assert_eq!(groups.len(), 1);
    assert_eq!(
        group.outer,
        ParsedInstruction::new(foreign(), numbered_accounts(2), vec![7, 1, 2, 3], Some(1))
    );
    assert_eq!(
        group.inner,
        vec![ParsedInstruction::new(
            spp(),
            numbered_accounts(3),
            vec![tag::TRANSACT, 1, 2, 3],
            Some(2)
        )]
    );
}

/// Each ring instruction puts `ring_config` at its own position; a shared
/// index would quietly attribute transactions to whatever account sits there.
#[test]
fn ring_config_comes_from_each_instruction_own_position() {
    for (source_tag, index) in [
        (tag::RING_TRANSACT, 5u8),
        (tag::RING_AUTHORITY_TRANSACT, 5),
        (tag::RING_DEPOSIT, 2),
        (tag::RING_MERGE_TRANSACT, 2),
    ] {
        assert_eq!(
            ring_config_of(source_tag, numbered_accounts(8)),
            Some(Pubkey::new_from_array([index; 32])),
            "tag {source_tag}"
        );
    }
}

/// The non-ring instructions pass no `ring_config`, so the slot at a ring
/// index holds an unrelated account and must not be read as one.
#[test]
fn instructions_without_a_ring_report_none() {
    for source_tag in [tag::TRANSACT, tag::DEPOSIT, tag::MERGE_TRANSACT] {
        assert_eq!(
            ring_config_of(source_tag, numbered_accounts(8)),
            None,
            "tag {source_tag}"
        );
    }
}

/// A truncated account list must not panic or report a wrong account.
#[test]
fn a_ring_instruction_missing_its_config_account_reports_none() {
    assert_eq!(
        ring_config_of(tag::RING_TRANSACT, numbered_accounts(4)),
        None
    );
}
