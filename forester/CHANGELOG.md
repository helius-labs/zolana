# Changelog

## [Unreleased]

- Nullifier PDAs are eleven bytes and start with a discriminator;
  `close-nullifier-pdas` skips accounts without it.
- Document that one cascade's append reimbursement goes to the triggering
  call's recipient.
