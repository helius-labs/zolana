# Protocol Config Invariants

Covers `CreateProtocolConfig` (tag 6) and `UpdateProtocolConfig` (tag 7). Shared
invariants (PDA cold path, canonical bump, loader checks, rollback) live in
`cross-cutting.md`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec previously said `update_protocol_config`
"rewrites every authority and flag"; `docs/spec.md` now states one field per call and
the required co-signature for a `ProtocolAuthority` rotation, matching the code.

## CreateProtocolConfig

### Authorization

- [x] **INV-CREATE-PC-01: fee payer must sign**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `mollusk_protocol_config_rejects_every_account_privilege_downgrade`
  - Kind: precondition
  - Statement: `create_protocol_config` can only succeed when the first account (`fee_payer`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:15` (`fn process_create_protocol_config`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-PC-02: the signer must be the protocol authority it writes**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `protocol_config_rejects_a_signer_that_names_other_authorities`
  - Kind: precondition
  - Statement: `create_protocol_config` returns Err whenever the fee payer's address differs from `data.protocol_authority`.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:24-26` (`fn process_create_protocol_config`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: Critical (authority bootstrap)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-PC-10: on an upgradeable deployment, only the deploy upgrade authority may initialize**
  - Covered by: `program-tests/shielded-pool/tests/protocol_config/contract.rs` `create_rejects_a_fee_payer_that_is_not_the_upgrade_authority`, `create_accepts_the_upgrade_authority`, `create_skips_the_check_without_an_upgrade_authority`; loader-state fixtures in `xtask/src/init_protocol.rs` tests
  - Kind: precondition
  - Statement: when the program account is owned by the upgradeable BPF loader and its `ProgramData` names an upgrade authority, `create_protocol_config` returns Err for every fee payer other than that authority; a non-upgradeable deployment (localnet `--bpf-program`) or an unset authority (immutable program, LiteSVM harness) skips the check; a forged program/`ProgramData` account or truncated loader state fails closed. Loader state is decoded with the canonical `solana-loader-v3-interface` bincode type on-chain and in xtask.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:76-112` (`fn check_initialization_authority`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: Critical (authority bootstrap)
  - Suggested test: negative + positive + carve-out; harness: mollusk unit

### Account Constraints

- [x] **INV-CREATE-PC-03: system program account must be the system program**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `protocol_config_requires_system_program_exactly`
  - Kind: precondition
  - Statement: `create_protocol_config` returns Err whenever the third account's address is not the system program id.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:21-23` (`fn process_create_protocol_config`)
  - Error: `ProgramError::IncorrectProgramId`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-PC-04: config address must be the canonical protocol-config PDA**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `protocol_config_creation_rejects_a_non_canonical_pda`
  - Kind: precondition
  - Statement: `create_protocol_config` returns Err whenever the config account's address differs from the PDA derived via `find_program_address([b"protocol_config"])`; the canonical bump is derived, never taken from instruction data.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:29-33` (`fn process_create_protocol_config`), `shared.rs:213-226` (`fn verify_pda`)
  - Error: `ShieldedPoolError::InvalidPda = 7016`
  - Severity: Critical (singleton authority oracle)
  - Suggested test: negative (non-canonical bump address); harness: mollusk unit

### Instruction Data Validation

- [x] **INV-CREATE-PC-05: payload must be exactly the struct size**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `protocol_config_creation_rejects_a_payload_of_the_wrong_size`
  - Kind: precondition
  - Statement: every payload whose length differs from exactly `size_of::<CreateProtocolConfigData>()` (131 bytes) makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:12-13` (`fn process_create_protocol_config`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-CREATE-PC-06: every config field is initialized from instruction data**
  - Covered by: `program-tests/shielded-pool/tests/protocol_config/contract.rs` `create_and_update_protocol_config`
  - Kind: postcondition
  - Statement: after a successful `create_protocol_config`, the config account has discriminator exactly 3 and each of the seven remaining fields (`protocol_authority`, `tree_creation_authority`, `tree_creation_is_permissionless`, `forester_authority`, `zone_creation_authority`, `zone_creation_is_permissionless`, `spl_interface_creation_is_permissionless`) exactly equal to the corresponding instruction-data field.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:46-55` (`fn process_create_protocol_config`), `protocol_config/init.rs:20-39` (`fn ProtocolConfigInitParams::init`)
  - Severity: High
  - Suggested test: positive (full struct compare); harness: mollusk unit

- [x] **INV-CREATE-PC-07: the created account size is exactly ProtocolConfig::SIZE**
  - Covered by: `program-tests/shielded-pool/tests/admin/functional.rs` `protocol_config_creation_initializes_complete_state` (extended with the owner-is-program assertion)
  - Kind: postcondition
  - Statement: after a successful `create_protocol_config`, the config account's `data_len` is exactly `ProtocolConfig::SIZE` (132) and its owner is the shielded-pool program.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:35-44` (`fn process_create_protocol_config`), `program-libs/interface/src/state/protocol_config.rs:77` (SIZE assert)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit

- [x] **INV-CREATE-PC-08: re-initialization is impossible**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `duplicate_protocol_config_creation_is_rejected`
  - Kind: precondition
  - Statement: `create_protocol_config` on an account whose first byte is not 0 (already stamped) returns Err and leaves the stored authorities unchanged; creation of an account that already exists with data fails in the system-program account-creation CPI (the `CreatePdaAccount` cold path's `Allocate` leg).
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:35-44` (`fn process_create_protocol_config`; creation CPI via `CreatePdaAccount`, `shared.rs:161-208`), `protocol_config/init.rs:24-26` (zeroed-buffer check)
  - Error: system-program `AccountAlreadyInUse` (`Custom(0)`) propagated from the failed creation CPI — the code maps a creation-CPI error to `ShieldedPoolError::InvalidProtocolConfig = 7012` (`create.rs:44`), but a failed inner CPI surfaces its own error rather than the caller's mapping, so the observed code is the system program's (pinned by the covering test); the zeroed-buffer check returns 7012 defensively
  - Severity: Critical (authority takeover via re-init)
  - Suggested test: negative (call twice); harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [x] **INV-CREATE-PC-09: only the config and fee-payer lamports change**
  - Covered by: `program-tests/shielded-pool/tests/admin/functional.rs` `protocol_config_creation_changes_only_the_config_and_fee_payer`
  - Kind: frame
  - Statement: after a successful `create_protocol_config`, every account other than the created config account and the fee payer (rent funding) has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/create.rs:11-56` (`fn process_create_protocol_config`)
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

## UpdateProtocolConfig

### Authorization

- [x] **INV-UPDATE-PC-01: only the current protocol authority may update**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `protocol_authority_rotation_revokes_old_authority`
  - Kind: precondition
  - Statement: `update_protocol_config` returns Err for every signer whose address differs from the stored `protocol_authority`.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/update.rs:22` (`fn process_update_protocol_config`), `loader.rs:55-67` (`fn load_and_validate_protocol_authority_mut`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: Critical (authority takeover)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-UPDATE-PC-02: rotating the protocol authority requires the new authority's signature**
  - Covered by: `program-tests/shielded-pool/tests/protocol_config/contract.rs` `create_and_update_protocol_config`
  - Kind: precondition
  - Statement: for the `ProtocolAuthority(a)` variant, a third account must be a signer whose address equals exactly `a`; a missing account, a non-signer, or an address mismatch returns Err.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/update.rs:15-20` (`fn process_update_protocol_config`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000` (mismatch); account-checks error (missing/non-signer)
  - Severity: Critical (bricking the authority with an unowned key)
  - Suggested test: negative all three ways; harness: mollusk unit

### Account Constraints

- [x] **INV-UPDATE-PC-03: config account must be writable, program-owned, sized, and stamped**
  - Covered by: `program-tests/shielded-pool/tests/protocol_config/contract.rs` `update_rejects_a_wrong_size_config_account`, `update_rejects_a_cosplay_config_account`
  - Kind: precondition
  - Statement: `update_protocol_config` returns Err whenever the config account is not writable, not owned by the program, has `data_len` different from exactly 132, or has a first byte different from exactly 3.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/loader.rs:26-34` (`fn load_protocol_config_mut`), `shared.rs:58-69` (`fn load_config_mut`)
  - Error: `ShieldedPoolError::InvalidProtocolConfig = 7012`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-UPDATE-PC-04: malformed borsh payload is rejected**
  - Covered by: `program-tests/shielded-pool/tests/protocol_config/contract.rs` `update_rejects_a_malformed_borsh_payload`
  - Kind: precondition
  - Statement: every payload that `UpdateProtocolConfigData::try_from_slice` fails to parse (unknown enum tag, truncated address) makes the instruction return Err.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/update.rs:9-10` (`fn process_update_protocol_config`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative + fuzz; harness: mollusk unit

### Success Postconditions

- [x] **INV-UPDATE-PC-05: exactly the addressed field takes the supplied value**
  - Covered by: `program-tests/shielded-pool/tests/protocol_config/contract.rs` `create_and_update_protocol_config`
  - Kind: postcondition
  - Statement: after a successful `update_protocol_config` with variant V carrying value v, the config field addressed by V is exactly v (booleans stored as exactly 0 or 1).
  - Location: `programs/shielded-pool/src/instructions/protocol_config/update.rs:23-37` (`fn process_update_protocol_config`)
  - Severity: High
  - Suggested test: positive per variant (all 7); harness: mollusk unit

### Frame Conditions

- [x] **INV-UPDATE-PC-06: every other config field is unchanged**
  - Covered by: `program-tests/shielded-pool/tests/protocol_config/contract.rs` `create_and_update_protocol_config`
  - Kind: frame
  - Statement: after a successful `update_protocol_config` with variant V, every config field other than the one addressed by V is unchanged, and every account other than the config account is unchanged.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/update.rs:23-37` (`fn process_update_protocol_config`)
  - Severity: High
  - Suggested test: positive per variant (full struct compare); harness: mollusk unit

### Reachability

- [x] **INV-UPDATE-PC-07: the protocol authority can always rotate itself**
  - Covered by: `program-tests/shielded-pool/tests/protocol_config/contract.rs` `create_and_update_protocol_config`
  - Kind: reachability
  - Statement: for every initialized protocol config, an `update_protocol_config(ProtocolAuthority(new))` signed by the current authority and by `new` succeeds, and afterward the old authority can no longer update the config while `new` can.
  - Location: `programs/shielded-pool/src/instructions/protocol_config/update.rs:15-24`
  - Severity: High
  - Suggested test: positive (rotate, then negative with old key); harness: mollusk unit
