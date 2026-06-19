# Summary
- Account validation for Solana programs over a single concrete account type: `solana_account_view::AccountView` (re-exported as `light_account_checks::AccountView`)
- Validation checks with 8-byte discriminators for account type safety
- AccountIterator providing detailed error locations (file:line:column)
- Error codes 20000-20015 (with gaps) with automatic ProgramError conversion

# Used in
- `light-batched-merkle-tree` - Batch operation account checks

# Navigation
- This file: Overview and module organization
- For detailed documentation on specific components, see the `docs/` directory:
  - `docs/CLAUDE.md` - Navigation guide for detailed documentation
  - `docs/ACCOUNT_CHECKS.md` - Account validation functions and patterns
  - `docs/ACCOUNT_ITERATOR.md` - Enhanced iterator with error reporting
  - `docs/ERRORS.md` - Error codes (20000-20015), causes, and resolutions
  - `docs/DISCRIMINATOR.md` - Discriminator trait for account type identification
  - `docs/PACKED_ACCOUNTS.md` - Index-based account access utility

# Source Code Structure

## Core Types (`src/`)

### Account Type (`account_info/`)
- `mod.rs` - Re-exports `solana_account_view::AccountView`, the single account type all checks operate on
- `test_account_info.rs` - Test helpers for constructing `AccountView` values (feature: `test-only`)

### Validation Functions (`checks.rs`)
- Account initialization (`account_info_init` - sets discriminator on `&mut AccountView`)
- Ownership validation (`check_owner`, `check_program`)
- Permission checks (`check_mut`, `check_non_mut`, `check_signer`)
- Discriminator validation (`check_discriminator`, `set_discriminator`)
- Rent exemption checks (`check_account_balance_is_rent_exempt` - caller supplies the rent minimum)
- Combined validators (`check_account_info`, `check_account_info_mut`, `check_account_info_non_mut`)
- Initialization check (`check_data_is_zeroed`)

### Account Processing (`account_iterator.rs`)
- `AccountIterator<'info>` over `&[AccountView]` (not generic)
- Sequential account processing with enhanced error messages
- Named account retrieval with automatic validation
- Location tracking for debugging (file:line:column in errors)
- Convenience methods: `next_signer`, `next_mut`, `next_non_mut`
- Optional account handling (`next_option`, `next_option_mut`, `next_option_signer`)

### Account Type Identification (`discriminator.rs`)
- Discriminator trait for 8-byte account type prefixes
- Constant discriminator arrays for compile-time verification
- Integration with zero-copy deserialization

### Dynamic Access (`packed_accounts.rs`)
- `ProgramPackedAccounts<'info>` over `&[AccountView]`
- Index-based account access for dynamic account sets
- Bounds-checked retrieval with descriptive error messages

### Error Handling (`error.rs`)
- AccountError enum (codes 20000-20015, with gaps where variants were removed)
- Automatic conversion to `solana_program_error::ProgramError::Custom(u32)`
- `ProgramError(u32)` variant carries pass-through custom codes

## Feature Flags
- `std` - Enables std (default); without it the crate is `no_std`
- `msg` - Enables `AccountIterator` error logging via `solana-msg` with caller
  location (file:line:column, via `#[track_caller]`); active only with `std` (default)
- `test-only` - Enables test utilities (pulls in `rand` and `std`)
- Default: `std`, `msg`
