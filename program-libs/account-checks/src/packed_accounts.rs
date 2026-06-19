use solana_account_view::AccountView;

use crate::AccountError;

/// Dynamic accounts slice for index-based access
/// Contains mint, owner, delegate, merkle tree, and queue accounts
pub struct ProgramPackedAccounts<'info> {
    pub accounts: &'info [AccountView],
}

impl ProgramPackedAccounts<'_> {
    /// Get account by index with bounds checking
    #[track_caller]
    #[inline(never)]
    pub fn get(&self, index: usize, _name: &str) -> Result<&AccountView, AccountError> {
        self.accounts
            .get(index)
            .ok_or(AccountError::NotEnoughAccountKeys)
    }

    // TODO: add get_checked_account from  PackedAccounts.
    /// Get account by u8 index with bounds checking
    #[track_caller]
    #[inline(never)]
    pub fn get_u8(&self, index: u8, name: &str) -> Result<&AccountView, AccountError> {
        self.get(index as usize, name)
    }
}
