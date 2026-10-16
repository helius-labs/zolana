use bytemuck::Zeroable;
use custom_ring_interface::{
    CustomRingError, PolicyConfig, PolicyTableIxData, SourceSlot, N_SOURCE_SLOTS,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_ring_policy::{EncodedRuleTable, ListId, ListSet, PolicySource, SourceMap, TableParts};

use crate::instructions::loader::load_curator_registry;

pub(crate) struct BoundTable {
    pub rules: EncodedRuleTable,
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
}

/// The table must decode, and the sources map exactly the lists it references.
/// Boxed, the bound table stays off the caller's SBF stack frame.
#[inline(never)]
pub(crate) fn bind_table(
    table: &PolicyTableIxData,
    curators: &[AccountView],
) -> Result<Box<BoundTable>, ProgramError> {
    let rules = decode_table(table)?;
    let sources = resolve_sources(table, rules.referenced(), curators)?;
    Ok(Box::new(BoundTable { rules, sources }))
}

#[inline(never)]
fn decode_table(table: &PolicyTableIxData) -> Result<EncodedRuleTable, CustomRingError> {
    let rules = TableParts {
        rows: &table.rules,
        inline_assets: &table.inline_assets,
        inline_limits: &table.inline_limits,
        limits: &table.limits,
    }
    .encode()?;
    rules.decode()?;
    Ok(rules)
}

/// A curator slot stores the curator's registry root account, a curator of a curator never chains.
#[inline(never)]
fn resolve_sources(
    table: &PolicyTableIxData,
    referenced: ListSet,
    curators: &[AccountView],
) -> Result<[SourceSlot; N_SOURCE_SLOTS], ProgramError> {
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    let mut seen = ListSet::EMPTY;
    for spec in &table.sources {
        let list_id = ListId::try_from(spec.list_id).map_err(|_| CustomRingError::InvalidSource)?;
        if !referenced.contains(list_id) || seen.contains(list_id) {
            return Err(CustomRingError::InvalidSource.into());
        }
        seen = seen.union(ListSet::single(list_id));
        let registry = match spec.source {
            0 => Address::default(),
            n => {
                let curator = curators
                    .get(usize::from(n) - 1)
                    .ok_or(CustomRingError::InvalidSource)?;
                load_curator_registry(curator)?
            }
        };
        sources[list_id.slot()] = SourceSlot {
            list_id: list_id as u8,
            registry,
        };
    }
    if seen != referenced {
        return Err(CustomRingError::InvalidSource.into());
    }
    Ok(sources)
}

/// Pins the hash over the stored rules and `sources`, counting the write.
#[inline(never)]
pub(crate) fn repin(
    live: &mut PolicyConfig,
    sources: &[SourceSlot; N_SOURCE_SLOTS],
) -> ProgramResult {
    let generation = live
        .generation()
        .checked_add(1)
        .ok_or(CustomRingError::PolicyGenerationOverflow)?;
    live.policy_hash = compute_policy_hash(&live.rules, sources)?;
    live.sources = *sources;
    live.generation = generation.to_le_bytes();
    live.generation_slot = Clock::get()?.slot.to_le_bytes();
    Ok(())
}

/// The hash binds the map rebuilt from the stored `(list_id, registry)` slots.
#[inline(never)]
pub(crate) fn compute_policy_hash(
    rules: &EncodedRuleTable,
    sources: &[SourceSlot; N_SOURCE_SLOTS],
) -> Result<[u8; 32], CustomRingError> {
    let mut slots = [PolicySource::default(); N_SOURCE_SLOTS];
    for (slot, source) in slots.iter_mut().zip(sources) {
        *slot = source.policy_source()?;
    }
    let map = SourceMap::from_slots(slots)?;
    Ok(rules.hash(&map)?)
}
