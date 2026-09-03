//! Locating self-emitted events in a transaction.
//!
//! The shielded pool emits events by re-invoking itself with an `EMIT_EVENT`
//! instruction, so an event is an inner instruction and its payload is
//! attacker-reachable: any program can CPI the pool with `EMIT_EVENT` and
//! forged bytes. What cannot be forged is the *parent*: an `EMIT_EVENT` is only
//! trustworthy when the instruction that invoked it is a genuine
//! state-transitioning instruction of the pool itself. Every event parser must
//! go through [`find_event_sites`] so that rule is applied in one place.

use crate::ingester::{
    error::IngesterError,
    typedefs::block_info::{
        Instruction as PhotonInstruction, InstructionGroup as PhotonInstructionGroup,
    },
};
use solana_pubkey::Pubkey;
use zolana_event::{
    tag, tag::InstructionTag, InstructionGroup as RingsInstructionGroup,
    ParsedInstruction as RingsInstruction,
};

pub struct EventSite {
    /// Tag of the instruction that emitted this event.
    pub source_instruction_tag: u8,
    /// The ring's `ring_auth` PDA, for ring instructions only.
    pub ring_config: Option<Pubkey>,
    /// Event bytes: `[kind, borsh(body)]`, i.e. the `EMIT_EVENT` instruction
    /// data with the tag byte removed.
    pub payload: Vec<u8>,
    /// The instruction that emitted this event, with its tag byte, and its
    /// account list. `transact` and `merge` log only the positions execution
    /// assigns, so the rest of the event is rebuilt from these.
    pub parent_data: Vec<u8>,
    pub parent_accounts: Vec<Pubkey>,
}

pub fn to_rings_instruction_groups(
    groups: &[PhotonInstructionGroup],
) -> Vec<RingsInstructionGroup> {
    let to_rings_instruction = |instruction: &PhotonInstruction| {
        RingsInstruction::new(
            instruction.program_id,
            instruction.accounts.clone(),
            instruction.data.clone(),
            instruction.stack_height,
        )
    };

    groups
        .iter()
        .map(|group| RingsInstructionGroup {
            outer: to_rings_instruction(&group.outer_instruction),
            inner: group
                .inner_instructions
                .iter()
                .map(to_rings_instruction)
                .collect(),
        })
        .collect()
}

/// Collect every `EMIT_EVENT` whose parent is an instruction of
/// `rings_program_id` with a tag `is_source_tag` accepts. `is_source_tag` must
/// never accept `EMIT_EVENT` itself, or an event could parent another.
pub fn find_event_sites(
    groups: &[RingsInstructionGroup],
    rings_program_id: Pubkey,
    is_source_tag: impl Fn(u8) -> bool,
) -> Result<Vec<EventSite>, IngesterError> {
    let mut sites = Vec::new();

    for group in groups {
        for (index, instruction) in group.inner.iter().enumerate() {
            if !is_emit_event(rings_program_id, instruction) {
                continue;
            }

            let Some(parent) = event_parent(group, index)? else {
                continue;
            };

            if parent.program_id != rings_program_id {
                continue;
            }

            let source_instruction_tag = parent.data.first().copied().ok_or_else(|| {
                IngesterError::ParserError(
                    "Rings event parent instruction is missing source tag".to_string(),
                )
            })?;

            if !is_source_tag(source_instruction_tag) {
                continue;
            }

            sites.push(EventSite {
                source_instruction_tag,
                ring_config: ring_config_index(source_instruction_tag)
                    .and_then(|index| parent.accounts.get(index).copied()),
                payload: instruction.data.get(1..).unwrap_or_default().to_vec(),
                parent_data: parent.data.clone(),
                parent_accounts: parent.accounts.clone(),
            });
        }
    }

    Ok(sites)
}

fn event_parent(
    group: &RingsInstructionGroup,
    event_index: usize,
) -> Result<Option<&RingsInstruction>, IngesterError> {
    let event_instruction = group.inner.get(event_index).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Rings event index {} is out of bounds for {} inner instructions",
            event_index,
            group.inner.len()
        ))
    })?;
    let Some(event_height) = event_instruction.stack_height else {
        return Ok(None);
    };
    let Some(parent_height) = event_height.checked_sub(1) else {
        return Ok(None);
    };
    let previous_instructions = group.inner.get(..event_index).ok_or_else(|| {
        IngesterError::ParserError(format!(
            "Rings event parent search index {} is out of bounds for {} inner instructions",
            event_index,
            group.inner.len()
        ))
    })?;

    Ok(previous_instructions
        .iter()
        .rev()
        .find(|instruction| instruction.stack_height == Some(parent_height))
        .or_else(|| (group.outer.stack_height == Some(parent_height)).then_some(&group.outer)))
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

fn is_emit_event(rings_program_id: Pubkey, instruction: &RingsInstruction) -> bool {
    instruction.program_id == rings_program_id && instruction.data.first() == Some(&tag::EMIT_EVENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_event::{InstructionGroup, ParsedInstruction};
    use zolana_interface::pda;

    fn spp() -> Pubkey {
        pda::shielded_pool_program_id()
    }

    /// Stand-in for any foreign program (attacker contract, ring program).
    fn foreign() -> Pubkey {
        Pubkey::new_from_array([9; 32])
    }

    fn ix(program_id: Pubkey, tag_byte: u8, stack_height: u32) -> ParsedInstruction {
        ParsedInstruction::new(
            program_id,
            Vec::new(),
            vec![tag_byte, 1, 2, 3],
            Some(stack_height),
        )
    }

    fn event_sites(groups: &[InstructionGroup]) -> Vec<EventSite> {
        find_event_sites(groups, spp(), |source| source == tag::TRANSACT).unwrap()
    }

    fn ring_sites(source_tag: u8, accounts: Vec<Pubkey>) -> Vec<EventSite> {
        let mut source = ix(spp(), source_tag, 2);
        source.accounts = accounts;
        let groups = [InstructionGroup {
            outer: ix(foreign(), 0, 1),
            inner: vec![source, ix(spp(), tag::EMIT_EVENT, 3)],
        }];
        find_event_sites(&groups, spp(), |tag| tag == source_tag).unwrap()
    }

    fn numbered_accounts(count: u8) -> Vec<Pubkey> {
        (0..count)
            .map(|i| Pubkey::new_from_array([i; 32]))
            .collect()
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
            let sites = ring_sites(source_tag, numbered_accounts(8));
            assert_eq!(sites.len(), 1, "tag {source_tag}");
            assert_eq!(
                sites[0].ring_config,
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
            let sites = ring_sites(source_tag, numbered_accounts(8));
            assert_eq!(sites.len(), 1, "tag {source_tag}");
            assert_eq!(sites[0].ring_config, None, "tag {source_tag}");
        }
    }

    /// A truncated account list must not panic or report a wrong account.
    #[test]
    fn a_ring_instruction_missing_its_config_account_reports_none() {
        let sites = ring_sites(tag::RING_TRANSACT, numbered_accounts(4));

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].ring_config, None);
    }

    #[test]
    fn accepts_genuine_self_emitted_event() {
        let groups = [InstructionGroup {
            outer: ix(spp(), tag::TRANSACT, 1),
            inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
        }];

        let sites = event_sites(&groups);

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].source_instruction_tag, tag::TRANSACT);
    }

    #[test]
    fn accepts_event_nested_at_height_three() {
        let groups = [InstructionGroup {
            outer: ix(foreign(), 0, 1),
            inner: vec![ix(spp(), tag::TRANSACT, 2), ix(spp(), tag::EMIT_EVENT, 3)],
        }];

        let sites = event_sites(&groups);

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].source_instruction_tag, tag::TRANSACT);
    }

    #[test]
    fn drops_event_whose_source_tag_is_rejected() {
        let groups = [InstructionGroup {
            outer: ix(spp(), tag::DEPOSIT, 1),
            inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
        }];

        assert!(event_sites(&groups).is_empty());
    }

    #[test]
    fn drops_event_forged_by_direct_foreign_cpi() {
        // Attacker program CPIs SPP with EMIT_EVENT; the event's parent is the
        // attacker's top-level instruction.
        let groups = [InstructionGroup {
            outer: ix(foreign(), 0, 1),
            inner: vec![ix(spp(), tag::EMIT_EVENT, 2)],
        }];

        assert!(event_sites(&groups).is_empty());
    }

    #[test]
    fn drops_event_forged_under_a_foreign_inner_parent() {
        // Attacker nests one level deeper so the forged event's stack height
        // matches the genuine ring-rail shape; the parent is still foreign.
        let groups = [InstructionGroup {
            outer: ix(foreign(), 0, 1),
            inner: vec![ix(foreign(), 0, 2), ix(spp(), tag::EMIT_EVENT, 3)],
        }];

        assert!(event_sites(&groups).is_empty());
    }

    #[test]
    fn drops_event_parented_to_another_emit_event() {
        // A second EMIT_EVENT whose reconstructed parent is the first
        // EMIT_EVENT: no caller accepts EMIT_EVENT as a source tag.
        let groups = [InstructionGroup {
            outer: ix(spp(), tag::TRANSACT, 1),
            inner: vec![ix(spp(), tag::EMIT_EVENT, 2), ix(spp(), tag::EMIT_EVENT, 3)],
        }];

        let sites = event_sites(&groups);

        assert_eq!(sites.len(), 1);
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

        assert!(event_sites(&groups).is_empty());
    }
}
