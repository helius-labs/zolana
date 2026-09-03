use pinocchio::{error::ProgramError, AccountView};
use zolana_interface::instruction::instruction_data::transact::{
    ResolvedOutput, TransactIxDataRef,
};

pub struct TreeWrite {
    pub first_output_leaf_index: u64,
}

/// Resolve every output's owner tag against the raw account list.
///
/// One exact-capacity heap allocation rather than a `MAX_OUTPUTS`-sized stack
/// buffer, which returned by value into the processor's frame and so grew with
/// the output count. The allocation stays until the external data hash stops
/// consuming resolved tags and the event stops republishing them; until then
/// resolving lazily is impossible, because the account list is borrowed mutably
/// before two of the three consumers run and an owner tag may reference any
/// account.
#[inline(never)]
pub(crate) fn resolve_outputs<'a>(
    accounts: &[AccountView],
    ix: &TransactIxDataRef<'a>,
) -> Result<Vec<ResolvedOutput<'a>>, ProgramError> {
    let mut outputs = Vec::with_capacity(ix.bound.outputs.len());
    for output in &ix.bound.outputs {
        outputs.push(
            output
                .into_resolved(|i| accounts.get(usize::from(i)).map(|a| a.address().to_bytes()))?,
        );
    }
    Ok(outputs)
}
