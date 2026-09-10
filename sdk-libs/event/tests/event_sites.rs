//! `find_event_sites` accepts an `EMIT_EVENT` only under a genuine pool parent.
//!
//! An event payload is attacker-reachable: any program can CPI the pool with
//! `EMIT_EVENT` and forged bytes. The parent cannot be forged, so these tests
//! pin the parent rule for every shape a forger could produce.

use solana_address::Address;
use zolana_event::{find_event_sites, EventSite, InstructionGroup, ParsedInstruction};
use zolana_interface::instruction::tag;

fn spp() -> Address {
    Address::new_from_array([1; 32])
}

fn foreign() -> Address {
    Address::new_from_array([9; 32])
}

fn ix(program_id: Address, tag_byte: u8, stack_height: u32) -> ParsedInstruction {
    ParsedInstruction::new(
        program_id,
        Vec::new(),
        vec![tag_byte, 1, 2, 3],
        Some(stack_height),
    )
}

fn transact_sites(groups: &[InstructionGroup]) -> Vec<EventSite<'_>> {
    find_event_sites(spp(), groups, |source| source == tag::TRANSACT)
}

#[test]
fn accepts_genuine_self_emitted_event() {
    let groups = [InstructionGroup {
        outer: ix(spp(), tag::TRANSACT, 1),
        inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
    }];

    let sites = transact_sites(&groups);

    let site = sites.first().expect("one event site");
    assert_eq!(sites.len(), 1);
    assert_eq!(site.source_instruction_tag, tag::TRANSACT);
    assert_eq!(site.payload, &[1, 2, 3]);
    assert_eq!(site.parent, &groups[0].outer);
}

#[test]
fn accepts_event_nested_at_height_three() {
    let groups = [InstructionGroup {
        outer: ix(foreign(), 0, 1),
        inner: vec![ix(spp(), tag::TRANSACT, 2), ix(spp(), tag::EMIT_EVENT, 3)],
    }];

    let sites = transact_sites(&groups);

    let site = sites.first().expect("one event site");
    assert_eq!(sites.len(), 1);
    assert_eq!(site.source_instruction_tag, tag::TRANSACT);
    assert_eq!(site.parent, groups[0].inner.first().expect("pool parent"));
}

#[test]
fn drops_event_whose_source_tag_is_rejected() {
    let groups = [InstructionGroup {
        outer: ix(spp(), tag::DEPOSIT, 1),
        inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
    }];

    assert!(transact_sites(&groups).is_empty());
}

#[test]
fn drops_event_forged_by_direct_foreign_cpi() {
    let groups = [InstructionGroup {
        outer: ix(foreign(), 0, 1),
        inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
    }];

    assert!(transact_sites(&groups).is_empty());
}

#[test]
fn drops_event_forged_under_a_foreign_inner_parent() {
    let groups = [InstructionGroup {
        outer: ix(foreign(), 0, 1),
        inner: vec![ix(foreign(), 0, 2), ix(spp(), tag::EMIT_EVENT, 3)],
    }];

    assert!(transact_sites(&groups).is_empty());
}

#[test]
fn drops_event_parented_to_another_emit_event() {
    let groups = [InstructionGroup {
        outer: ix(spp(), tag::TRANSACT, 1),
        inner: vec![ix(spp(), tag::EMIT_EVENT, 2), ix(spp(), tag::EMIT_EVENT, 3)],
    }];

    assert_eq!(transact_sites(&groups).len(), 1);
}

#[test]
fn drops_emit_event_of_a_foreign_program() {
    let groups = [InstructionGroup {
        outer: ix(spp(), tag::TRANSACT, 1),
        inner: vec![ix(foreign(), tag::EMIT_EVENT, 2)],
    }];

    assert!(transact_sites(&groups).is_empty());
}

#[test]
fn drops_event_without_stack_height() {
    let groups = [InstructionGroup {
        outer: ix(spp(), tag::TRANSACT, 1),
        inner: vec![ParsedInstruction::new(
            spp(),
            Vec::new(),
            vec![tag::EMIT_EVENT],
            None,
        )],
    }];

    assert!(transact_sites(&groups).is_empty());
}

#[test]
fn drops_event_whose_parent_has_no_tag() {
    let groups = [InstructionGroup {
        outer: ParsedInstruction::new(spp(), Vec::new(), Vec::new(), Some(1)),
        inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
    }];

    assert!(find_event_sites(spp(), &groups, |_| true).is_empty());
}

#[test]
fn parent_is_the_nearest_preceding_instruction_one_level_up() {
    let groups = [InstructionGroup {
        outer: ix(foreign(), 0, 1),
        inner: vec![
            ix(spp(), tag::DEPOSIT, 2),
            ix(spp(), tag::TRANSACT, 2),
            ix(spp(), tag::EMIT_EVENT, 3),
        ],
    }];

    let sites = find_event_sites(spp(), &groups, |_| true);

    let site = sites.first().expect("one event site");
    assert_eq!(sites.len(), 1);
    assert_eq!(site.source_instruction_tag, tag::TRANSACT);
}
