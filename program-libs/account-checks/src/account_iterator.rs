use core::panic::Location;

use solana_account_view::AccountView;

use crate::{
    checks::{check_mut, check_non_mut, check_signer},
    AccountError,
};

/// Iterator over accounts that provides detailed error messages when accounts are missing.
///
/// This iterator helps with debugging account setup issues by tracking which accounts
/// are requested and providing clear error messages when there are insufficient accounts.
pub struct AccountIterator<'info> {
    /// The not-yet-yielded accounts. Shrinks from the front on every step.
    accounts: &'info mut [AccountView],
    /// Number of accounts already yielded; used for diagnostics only.
    position: usize,
    #[allow(unused)]
    owner: [u8; 32],
}

impl<'info> AccountIterator<'info> {
    /// Create a new AccountIterator from a slice of AccountView.
    #[inline(always)]
    pub fn new(accounts: &'info mut [AccountView]) -> Self {
        Self {
            accounts,
            position: 0,
            owner: [0; 32],
        }
    }

    #[inline(always)]
    pub fn new_with_owner(accounts: &'info mut [AccountView], owner: [u8; 32]) -> Self {
        Self {
            accounts,
            position: 0,
            owner,
        }
    }

    /// Get the next account with a descriptive name.
    ///
    /// # Arguments
    /// * `account_name` - A descriptive name for the account being requested (for debugging)
    ///
    /// # Returns
    /// * `Ok(&mut AccountView)` - The next account in the iterator
    /// * `Err(AccountError::NotEnoughAccountKeys)` - If no more accounts are available
    #[track_caller]
    #[inline(always)]
    pub fn next_account(
        &mut self,
        account_name: &str,
    ) -> Result<&'info mut AccountView, AccountError> {
        // Take the remaining slice out so we can peel off the front element with a
        // `'info` lifetime, then store the tail back. `&mut [T]: Default` yields an
        // empty slice, so the iterator is left empty if this is the last element.
        let accounts = core::mem::take(&mut self.accounts);
        match accounts.split_first_mut() {
            Some((account, rest)) => {
                self.accounts = rest;
                self.position += 1;
                Ok(account)
            }
            None => {
                self.print_not_enough_accounts(account_name, Location::caller());
                Err(AccountError::NotEnoughAccountKeys)
            }
        }
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_checked_pubkey(
        &mut self,
        account_name: &str,
        pubkey: [u8; 32],
    ) -> Result<&'info mut AccountView, AccountError> {
        let account_info = self.next_account(account_name)?;
        if account_info.address().to_bytes() != pubkey {
            self.print_on_error_pubkey(
                &AccountError::InvalidAccount,
                account_info.address().to_bytes(),
                pubkey,
                account_name,
                Location::caller(),
            );
            return Err(AccountError::InvalidAccount);
        }
        Ok(account_info)
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_option(
        &mut self,
        account_name: &str,
        is_some: bool,
    ) -> Result<Option<&'info mut AccountView>, AccountError> {
        if is_some {
            let account_info = self.next_account(account_name)?;
            Ok(Some(account_info))
        } else {
            Ok(None)
        }
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_option_mut(
        &mut self,
        account_name: &str,
        is_some: bool,
    ) -> Result<Option<&'info mut AccountView>, AccountError> {
        if is_some {
            let account_info = self.next_mut(account_name)?;
            Ok(Some(account_info))
        } else {
            Ok(None)
        }
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_option_signer(
        &mut self,
        account_name: &str,
        is_some: bool,
    ) -> Result<Option<&'info mut AccountView>, AccountError> {
        if is_some {
            let account_info = self.next_signer(account_name)?;
            Ok(Some(account_info))
        } else {
            Ok(None)
        }
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_signer_mut(
        &mut self,
        account_name: &str,
    ) -> Result<&'info mut AccountView, AccountError> {
        let account_info = self.next_signer(account_name)?;
        check_mut(account_info)
            .inspect_err(|e| self.print_on_error(e, account_name, Location::caller()))?;
        Ok(account_info)
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_signer(
        &mut self,
        account_name: &str,
    ) -> Result<&'info mut AccountView, AccountError> {
        let account_info = self.next_account(account_name)?;
        check_signer(account_info)
            .inspect_err(|e| self.print_on_error(e, account_name, Location::caller()))?;
        Ok(account_info)
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_signer_non_mut(
        &mut self,
        account_name: &str,
    ) -> Result<&'info mut AccountView, AccountError> {
        let account_info = self.next_signer(account_name)?;
        check_non_mut(account_info)
            .inspect_err(|e| self.print_on_error(e, account_name, Location::caller()))?;
        Ok(account_info)
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_non_mut(
        &mut self,
        account_name: &str,
    ) -> Result<&'info mut AccountView, AccountError> {
        let account_info = self.next_account(account_name)?;
        check_non_mut(account_info)
            .inspect_err(|e| self.print_on_error(e, account_name, Location::caller()))?;
        Ok(account_info)
    }

    #[inline(always)]
    #[track_caller]
    pub fn next_mut(&mut self, account_name: &str) -> Result<&'info mut AccountView, AccountError> {
        let account_info = self.next_account(account_name)?;
        check_mut(account_info)
            .inspect_err(|e| self.print_on_error(e, account_name, Location::caller()))?;
        Ok(account_info)
    }

    /// Get all remaining accounts in the iterator.
    #[inline(always)]
    #[track_caller]
    pub fn remaining(self) -> Result<&'info [AccountView], AccountError> {
        if self.accounts.is_empty() {
            self.print_not_enough_accounts("remaining accounts", Location::caller());
            return Err(AccountError::NotEnoughAccountKeys);
        }
        Ok(self.accounts)
    }

    /// Get all remaining accounts in the iterator as a mutable slice.
    #[inline(always)]
    #[track_caller]
    pub fn remaining_mut(self) -> Result<&'info mut [AccountView], AccountError> {
        if self.accounts.is_empty() {
            self.print_not_enough_accounts("remaining accounts", Location::caller());
            return Err(AccountError::NotEnoughAccountKeys);
        }
        Ok(self.accounts)
    }

    /// Get all remaining accounts in the iterator without validation.
    ///
    /// Returns an empty slice if the iterator is exhausted.
    #[inline(always)]
    #[track_caller]
    pub fn remaining_unchecked(self) -> Result<&'info [AccountView], AccountError> {
        Ok(self.accounts)
    }

    /// Get all remaining accounts in the iterator as a mutable slice without validation.
    ///
    /// Returns an empty slice if the iterator is exhausted.
    #[inline(always)]
    #[track_caller]
    pub fn remaining_unchecked_mut(self) -> Result<&'info mut [AccountView], AccountError> {
        Ok(self.accounts)
    }

    /// Get the current position in the iterator (number of accounts yielded so far).
    #[inline(always)]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get the total number of accounts the iterator was created with.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.position + self.accounts.len()
    }

    /// Check if the iterator was created with no accounts.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if all accounts have been yielded.
    #[inline(always)]
    pub fn iterator_is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    #[cold]
    fn print_not_enough_accounts(&self, account_name: &str, location: &Location) {
        #[cfg(all(feature = "msg", feature = "std"))]
        solana_msg::msg!(
            "ERROR: Not enough accounts. Requested '{}' at index {} but only {} accounts available. {}:{}:{}",
            account_name,
            self.position,
            self.len(),
            location.file(),
            location.line(),
            location.column()
        );
        #[cfg(not(all(feature = "msg", feature = "std")))]
        let _ = (account_name, location);
    }

    #[cold]
    fn print_on_error(&self, error: &AccountError, account_name: &str, location: &Location) {
        #[cfg(all(feature = "msg", feature = "std"))]
        solana_msg::msg!(
            "ERROR: {}. for account '{}' at index {}  {}:{}:{}",
            error,
            account_name,
            self.position.saturating_sub(1),
            location.file(),
            location.line(),
            location.column()
        );
        #[cfg(not(all(feature = "msg", feature = "std")))]
        let _ = (error, account_name, location);
    }

    #[cold]
    fn print_on_error_pubkey(
        &self,
        error: &AccountError,
        pubkey: [u8; 32],
        expected: [u8; 32],
        account_name: &str,
        location: &Location,
    ) {
        #[cfg(all(feature = "msg", feature = "std"))]
        solana_msg::msg!(
            "ERROR: {}. for account '{}' address: {:?}, expected: {:?}, at index {}  {}:{}:{}",
            error,
            account_name,
            solana_address::Address::new_from_array(pubkey),
            solana_address::Address::new_from_array(expected),
            self.position.saturating_sub(1),
            location.file(),
            location.line(),
            location.column()
        );
        #[cfg(not(all(feature = "msg", feature = "std")))]
        let _ = (error, pubkey, expected, account_name, location);
    }
}
