use crate::instructions::shared::caused_by;
use pinocchio::{account::RefMut, error::ProgramError, AccountView, ProgramResult};
use spr_interface::error::ShieldedPoolError;
use spr_tree::{TreeAccount, UNINITIALIZED};

/// What the first allocation step commits a tree creation to: its payer and
/// exact instruction data, which every later step must repeat, so no other
/// caller and no other parameters or fees can finish it. The record sits in
/// the not yet initialized utxo tree region and is zeroed before `init`.
pub(super) struct PendingCreation<'a> {
    pub payer: &'a AccountView,
    pub data: &'a [u8],
}

impl PendingCreation<'_> {
    /// The record's payer and data slots in `account`.
    fn slots<'b>(
        &self,
        account: &'b mut [u8],
    ) -> Result<(&'b mut [u8; 32], &'b mut [u8]), ProgramError> {
        let invalid = ShieldedPoolError::InvalidTreeAccounts;
        let (payer, rest) = account
            .get_mut(TreeAccount::utxo_tree_offset()..)
            .and_then(|record| record.split_first_chunk_mut::<32>())
            .ok_or(invalid)?;
        Ok((payer, rest.get_mut(..self.data.len()).ok_or(invalid)?))
    }

    #[inline(never)]
    pub fn record(&self, tree: &mut AccountView) -> ProgramResult {
        let mut account = borrow_mut(tree)?;
        let (payer, data) = self.slots(&mut account)?;
        *payer = *self.payer.address().as_array();
        data.copy_from_slice(self.data);
        Ok(())
    }

    /// Require a still uninitialized tree to hold this step's record.
    #[inline(never)]
    pub fn check(&self, tree: &mut AccountView) -> ProgramResult {
        let mut account = borrow_mut(tree)?;
        if account.get(1).copied() != Some(UNINITIALIZED) {
            return Err(ShieldedPoolError::InvalidTreeAccounts.into());
        }
        let (payer, data) = self.slots(&mut account)?;
        if payer != self.payer.address().as_array() || data != self.data {
            return Err(ShieldedPoolError::TreeCreationMismatch.into());
        }
        Ok(())
    }

    #[inline(never)]
    pub fn clear(&self, tree: &mut AccountView) -> ProgramResult {
        let mut account = borrow_mut(tree)?;
        let (payer, data) = self.slots(&mut account)?;
        payer.fill(0);
        data.fill(0);
        Ok(())
    }
}

#[track_caller]
fn borrow_mut(tree: &mut AccountView) -> Result<RefMut<'_, [u8]>, ProgramError> {
    tree.try_borrow_mut()
        .map_err(caused_by(ShieldedPoolError::InvalidTreeAccounts))
}
