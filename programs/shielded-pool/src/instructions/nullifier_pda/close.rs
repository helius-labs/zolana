use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_interface::error::ShieldedPoolError;

use super::loader::load_nullifier_pda;

pub(crate) struct NullifierPdaClose {
    pub tree_id: u16,
    pub close_before_index: u64,
}

impl NullifierPdaClose {
    #[inline(never)]
    pub(crate) fn close(
        &self,
        tree: &mut AccountView,
        nullifier_pda: &mut AccountView,
    ) -> ProgramResult {
        let record = load_nullifier_pda(nullifier_pda, self.tree_id)?;
        if !record.is_closable(self.close_before_index) {
            return Err(ShieldedPoolError::NullifierPdaNotClosable.into());
        }
        let tree_balance = tree
            .lamports()
            .checked_add(nullifier_pda.lamports())
            .ok_or(ProgramError::ArithmeticOverflow)?;
        tree.set_lamports(tree_balance);
        nullifier_pda.set_lamports(0);
        nullifier_pda.close()
    }
}
