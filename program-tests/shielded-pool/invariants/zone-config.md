# Zone Config Invariants

Covers `CreateZoneConfig` (tag 9), `UpdateZoneConfigOwner` (tag 10),
`UpdateZoneConfig` (tag 11). The shared zone-authorization pattern (signer +
owner/discriminator load, derivation checked only at creation) is INV-XC-26 in
`cross-cutting.md`.

## CreateZoneConfig

### Authorization

- [x] **INV-CREATE-ZC-01: payer must sign**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_config_creation_rejects_an_unsigned_payer`
  - Kind: precondition
  - Statement: `create_zone_config` can only succeed when the first account (`payer`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:15` (`fn process_create_zone_config`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-ZC-02: non-permissionless creation requires the zone-creation authority**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `zone_config_creation_rejects_an_unconfigured_payer_when_permissioned`
  - Kind: precondition
  - Statement: when `protocol_config.zone_creation_is_permissionless` is exactly 0, `create_zone_config` returns Err for every payer whose address differs from `protocol_config.zone_creation_authority`.
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:39-48` (`fn process_create_zone_config`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative + positive (flag set); harness: mollusk unit

- [x] **INV-CREATE-ZC-03: the zone_auth PDA must sign its own creation**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `zone_config_creation_rejects_an_unsigned_zone_config`
  - Kind: precondition
  - Statement: `create_zone_config` returns Err whenever the `zone_config` account is not a signer; only the zone program can produce that signature via `invoke_signed(["zone_auth", bump])`.
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:29-31` (`fn process_create_zone_config`)
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: Critical (zone identity binding)
  - Suggested test: negative; harness: mollusk unit

### Account Constraints

- [x] **INV-CREATE-ZC-04: config address must be the canonical zone_auth PDA of the declared program**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `zone_config_rejects_a_noncanonical_zone_authority_account`
  - Kind: precondition
  - Statement: `create_zone_config` returns Err whenever the `zone_config` account's address differs from `find_program_address([b"zone_auth"], data.program_id)`; this creation-time check is the sole place the derivation is ever verified, and the canonical bump is stored in the account.
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:34-37, 72-74` (`fn process_create_zone_config`, `fn derive_zone_auth`)
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: Critical (a config bound to the wrong program would authorize a foreign zone)
  - Suggested test: negative (PDA of a different program id); harness: mollusk unit

- [x] **INV-CREATE-ZC-05: system program account must be the system program**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_config_creation_rejects_a_wrong_system_program`
  - Kind: precondition
  - Statement: `create_zone_config` returns Err whenever the fourth account's address is not the system program id.
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:20-22` (`fn process_create_zone_config`)
  - Error: `ProgramError::IncorrectProgramId`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-CREATE-ZC-06: malformed borsh payload is rejected**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_config_creation_rejects_a_truncated_payload`
  - Kind: precondition
  - Statement: every payload that `CreateZoneConfigData::try_from_slice` fails to parse makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:12-13` (`fn process_create_zone_config`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative + fuzz; harness: mollusk unit

### Success Postconditions

- [x] **INV-CREATE-ZC-07: every config field is initialized exactly**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_config_creation_initializes_the_exact_account_state`
  - Kind: postcondition
  - Statement: after a successful `create_zone_config`, the account has discriminator exactly 4, `authority` exactly `data.authority`, `program_id` exactly `data.program_id`, `zone_authority_transact_is_enabled` exactly 0 or 1 per `data`, and `bump` exactly the canonical `zone_auth` bump; the account's `data_len` is exactly `ZoneConfig::SIZE` (67) and its owner is the shielded-pool program.
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:53-68` (`fn process_create_zone_config`), `zone_config/init.rs:15-34` (`fn ZoneConfigInitParams::init`)
  - Severity: High
  - Suggested test: positive (full struct compare); harness: mollusk unit

- [x] **INV-CREATE-ZC-08: a zone config cannot be created twice**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_config_creation_rejects_double_initialization`
  - Kind: precondition
  - Statement: a second `create_zone_config` for the same zone program returns Err and leaves the existing config unchanged (the account already exists and owns data, so the system-program account-creation CPI fails).
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:53-60` (`fn process_create_zone_config`)
  - Error: system-program `AccountAlreadyInUse` (`Custom(0)`) propagated from the failed creation CPI. The code maps a create-account CPI error to `ShieldedPoolError::InvalidZoneConfig = 7014` (`create.rs:60`), but a failed inner CPI surfaces its own error rather than the caller's mapping (solana-program-runtime `cpi.rs` propagates the inner instruction error out of the syscall), so the observed code is the system program's — pinned by the covering test, which reaches SPP through the zone-test-program fixture (the fixture forwards the instruction to SPP verbatim and performs no account creation of its own). The 7014 mapping does not surface on this path.
  - Severity: Critical (zone authority takeover via re-init)
  - Suggested test: negative (call twice); harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [x] **INV-CREATE-ZC-09: only the zone config and payer lamports change**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_config_creation_changes_only_the_config_and_payer`
  - Kind: frame
  - Statement: after a successful `create_zone_config`, every account other than the created `zone_config` and the `payer` (rent funding) has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/zone_config/create.rs:11-69`
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

## UpdateZoneConfigOwner

### Authorization

- [x] **INV-UPDATE-ZC-OWNER-01: only the current zone authority may rotate**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_owner_rotation_rejects_a_non_authority_signer`
  - Kind: precondition
  - Statement: `update_zone_config_owner` returns Err for every signer whose address differs from the stored `zone_config.authority`.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update_owner.rs:23` (`fn process_update_zone_config_owner`), `zone_config/loader.rs:36-48` (`fn load_and_validate_zone_authority_mut`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: Critical (zone authority takeover)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-UPDATE-ZC-OWNER-02: the new authority is read only from the co-signing account**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/update_owner.rs` (`reads_new_owner_only_from_the_signer_account`, `rejects_unsigned_new_owner`), `program-tests/shielded-pool/tests/admin/rejection.rs` `zone_owner_rotation_binds_the_new_owner_to_the_co_signing_account`
  - Kind: precondition
  - Statement: the new authority address comes ONLY from the third account, which must sign — there is no instruction-data field for it (PR172 removed the borsh payload, so the address can never be grafted from data the co-signer did not see); a missing or non-signing third account returns Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update_owner.rs` (`fn process_update_zone_config_owner`)
  - Error: account-checks signer error
  - Severity: High (prevents rotating to an unowned key)
  - Suggested test: negative (exists); harness: `cargo test -p shielded-pool-tests --test zone_config_update_owner`

### Instruction Data Validation

- [x] **INV-UPDATE-ZC-OWNER-05: any non-empty payload is rejected**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/update_owner.rs` `rejects_legacy_owner_payload`, `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_owner_rotation_rejects_a_legacy_payload`
  - Kind: precondition
  - Statement: the instruction data is exactly the tag byte; ANY trailing payload (including the retired borsh `UpdateZoneConfigOwnerData` encoding carried by pre-PR172 clients) makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update_owner.rs` (`fn process_update_zone_config_owner`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative (exists); harness: `cargo test -p shielded-pool-tests --test zone_config_update_owner`

### Success Postconditions

- [x] **INV-UPDATE-ZC-OWNER-03: the authority field takes exactly the new value**
  - Covered by: `program-tests/shielded-pool/tests/admin/functional.rs` `zone_config_owner_rotation_updates_authority`
  - Kind: postcondition
  - Statement: after a successful `update_zone_config_owner`, `zone_config.authority` is exactly `data.new_authority`, and afterward the old authority can no longer update the config while the new one can.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update_owner.rs:23-25` (`fn process_update_zone_config_owner`)
  - Severity: High
  - Suggested test: positive (rotate, then negative with old key); harness: mollusk unit

### Frame Conditions

- [x] **INV-UPDATE-ZC-OWNER-04: every other config field is unchanged**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_owner_rotation_changes_only_the_authority_field`
  - Kind: frame
  - Statement: after a successful `update_zone_config_owner`, the config's `discriminator`, `program_id`, `zone_authority_transact_is_enabled`, and `bump` are unchanged, and every other account is unchanged.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update_owner.rs:23-25`
  - Severity: High
  - Suggested test: positive (full struct compare); harness: mollusk unit

## UpdateZoneConfig

### Authorization

- [x] **INV-UPDATE-ZC-01: only the current zone authority may toggle**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `zone_config_owner_rotation_revokes_old_authority`
  - Kind: precondition
  - Statement: `update_zone_config` returns Err for every signer whose address differs from the stored `zone_config.authority`.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update.rs:15` (`fn process_update_zone_config`), `zone_config/loader.rs:36-48`
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Account Constraints

- [x] **INV-UPDATE-ZC-02: config account must be writable, program-owned, sized, and stamped**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `zone_update_rejects_a_cosplay_config_account`
  - Kind: precondition
  - Statement: `update_zone_config` (and `update_zone_config_owner`) returns Err whenever the config account is not writable, not owned by the program, has `data_len` different from exactly 67, or has a first byte different from exactly 4.
  - Location: `programs/shielded-pool/src/instructions/zone_config/loader.rs:23-31` (`fn load_zone_config_mut`)
  - Error: `ShieldedPoolError::InvalidZoneConfig = 7014`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-UPDATE-ZC-06: malformed borsh payload is rejected**
  - Covered by: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_config_update_rejects_a_truncated_payload`
  - Kind: precondition
  - Statement: every payload that `UpdateZoneConfigData::try_from_slice` fails to parse makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update.rs:9-10` (`fn process_update_zone_config`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative + fuzz; harness: mollusk unit

### Success Postconditions

- [x] **INV-UPDATE-ZC-03: the enabled flag takes exactly the supplied value**
  - Covered by: `program-tests/shielded-pool/tests/admin/functional.rs` `zone_config_update_changes_enabled_state`
  - Kind: postcondition
  - Statement: after a successful `update_zone_config`, `zone_authority_transact_is_enabled` is exactly 1 when `data.zone_authority_transact_is_enabled` is true and exactly 0 otherwise.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update.rs:16-17` (`fn process_update_zone_config`)
  - Severity: High
  - Suggested test: positive both values; harness: mollusk unit

### Frame Conditions

- [ ] **INV-UPDATE-ZC-04: every other config field is unchanged**
  - Partial coverage: `program-tests/shielded-pool/tests/admin/functional.rs` `zone_config_update_changes_enabled_state` (authority, bump, and discriminator compared; `program_id` is not)
  - Kind: frame
  - Statement: after a successful `update_zone_config`, the config's `discriminator`, `authority`, `program_id`, and `bump` are unchanged, and every other account is unchanged.
  - Location: `programs/shielded-pool/src/instructions/zone_config/update.rs:15-17`
  - Severity: High
  - Suggested test: positive (full struct compare); harness: mollusk unit

### Reachability

- [ ] **INV-UPDATE-ZC-05: burning the authority freezes the toggle permanently**
  - Partial coverage: `program-tests/shielded-pool/tests/zone_config/contract.rs` `zone_owner_burn_freezes_the_toggle_for_the_old_authority` (a true `Address::default()` burn is unreachable by construction — the incoming authority must co-sign and nothing signs for the default address, pinned by the test; a discarded-key burn locks the old authority out of toggle and rotation with 7003; post-burn `zone_transact`/`zone_deposit` availability not asserted)
  - Kind: reachability
  - Statement: after `update_zone_config_owner` sets `authority` to an address no one can sign for (e.g. `Address::default()`), no `update_zone_config` or `update_zone_config_owner` can ever succeed again for that zone, while `zone_transact`, `zone_deposit`, and `zone_merge_transact` remain available; `zone_authority_transact` remains exactly in its last-enabled state.
  - Location: `programs/shielded-pool/src/instructions/zone_config/loader.rs:36-48`, `docs/spec.md:1163-1164, 1200`
  - Severity: Medium (documented burn semantics)
  - Suggested test: positive (burn, then negative toggle, positive zone_transact); harness: program-tests integration (`cargo test-sbf`)
