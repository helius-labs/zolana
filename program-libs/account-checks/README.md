<!-- cargo-rdme start -->

# light-account-checks

Account validation for Solana programs over a concrete
[`solana_account_view::AccountView`].

| Module | Description |
|--------|-------------|
| [`AccountView`] | The account type all checks operate on (re-exported) |
| [`AccountIterator`] | Iterates over a slice of accounts by index |
| [`AccountError`] | Error type for account validation failures |
| [`checks`] | Owner, signer, writable, and rent-exempt checks |
| [`discriminator`] | Account discriminator constants and validation |
| [`packed_accounts`] | Packed account struct deserialization |

<!-- cargo-rdme end -->
