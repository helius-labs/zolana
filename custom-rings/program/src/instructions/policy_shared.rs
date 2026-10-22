use bytemuck::Zeroable;
use custom_ring_interface::{CustomRingError, PolicyTableIxData, SourceSlot, N_SOURCE_SLOTS};
use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_ring_policy::{EncodedRuleTable, ListId, ListSet, TableParts};

use crate::instructions::loader::load_curator_registry;

pub(crate) struct BoundTable {
    pub rules: EncodedRuleTable,
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
}

pub(crate) struct TableBinding<'a> {
    pub program_id: &'a Address,
    pub table: &'a PolicyTableIxData,
    pub curators: &'a [AccountView],
}

impl TableBinding<'_> {
    /// Boxed off the SBF stack, the sources name only lists the table references.
    #[inline(never)]
    pub fn bind(self) -> Result<Box<BoundTable>, ProgramError> {
        let table = self.table;
        let rules = TableParts {
            rows: &table.rules,
            inline_assets: &table.inline_assets,
            inline_limits: &table.inline_limits,
            limits: &table.limits,
        }
        .encode()
        .map_err(CustomRingError::from)?;
        let sources = self.sources(rules.referenced())?;
        Ok(Box::new(BoundTable { rules, sources }))
    }

    #[inline(never)]
    fn sources(&self, referenced: ListSet) -> Result<[SourceSlot; N_SOURCE_SLOTS], ProgramError> {
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        let mut seen = ListSet::EMPTY;
        // Lists sharing a curator load its registry once.
        let mut loaded: Vec<Address> = Vec::new();
        for spec in &self.table.sources {
            let list_id =
                ListId::try_from(spec.list_id).map_err(|_| CustomRingError::InvalidSource)?;
            if !referenced.contains(list_id) || seen.contains(list_id) {
                return Err(CustomRingError::InvalidSource.into());
            }
            seen = seen.union(ListSet::single(list_id));
            let registry = match spec.source {
                0 => Address::default(),
                n => {
                    let curator = self
                        .curators
                        .get(usize::from(n) - 1)
                        .ok_or(CustomRingError::InvalidSource)?;
                    if !loaded.contains(curator.address()) {
                        loaded.push(curator_source(self.program_id, curator)?);
                    }
                    *curator.address()
                }
            };
            sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                registry,
            };
        }
        Ok(sources)
    }
}

/// A curator source names another ring's registry, the own registry keeps its hard floor.
pub(crate) fn curator_source(
    program_id: &Address,
    curator: &AccountView,
) -> Result<Address, ProgramError> {
    if curator.owned_by(program_id) {
        return Err(CustomRingError::InvalidSource.into());
    }
    load_curator_registry(curator)?;
    Ok(*curator.address())
}
