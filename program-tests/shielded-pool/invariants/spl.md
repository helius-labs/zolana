# SPL Interface Invariants

Covers `CreateAssetCounter` (tag 16) and `CreateSplInterface` (tag 4). Shared
invariants (PDA cold path, canonical bump, rollback) live in `cross-cutting.md`.

SPEC_DIVERGENCE (resolved 2026-07-23): the spec's instruction table previously omitted
`create_asset_counter` (tag 16); `docs/spec.md` now lists it.

## CreateAssetCounter

### Authorization

- [x] **INV-CREATE-AC-01: authority must sign**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_rejects_an_unsigned_authority`
  - Kind: precondition
  - Statement: `create_asset_counter` can only succeed when the first account (`authority`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:19` (`fn process_create_asset_counter`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-AC-02: only the protocol authority may create the counter**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_rejects_a_non_protocol_authority`
  - Kind: precondition
  - Statement: `create_asset_counter` returns Err for every signer whose address differs from `protocol_config.protocol_authority`; there is no permissionless flag for this instruction.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:28-33` (`fn process_create_asset_counter`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Account Constraints

- [x] **INV-CREATE-AC-03: system program account must be the system program**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_rejects_a_wrong_system_program`
  - Kind: precondition
  - Statement: `create_asset_counter` returns Err whenever the fourth account's address is not the system program id.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:24-26` (`fn process_create_asset_counter`)
  - Error: `ProgramError::IncorrectProgramId`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-AC-04: counter address must be the canonical counter PDA**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `asset_counter_creation_rejects_a_non_canonical_pda`
  - Kind: precondition
  - Statement: `create_asset_counter` returns Err whenever the counter account's address differs from the PDA derived via `find_program_address([b"spl_asset_counter"])`; the canonical bump is derived, never supplied.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:35-39` (`fn process_create_asset_counter`)
  - Error: `ShieldedPoolError::InvalidPda = 7016`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-CREATE-AC-05: any payload byte is rejected**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_rejects_trailing_instruction_bytes`
  - Kind: precondition
  - Statement: `create_asset_counter` returns Err whenever the payload after the tag byte is non-empty.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:15-17` (`fn process_create_asset_counter`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-CREATE-AC-06: the counter is initialized to the first asset id**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_initializes_complete_state`
  - Kind: postcondition
  - Statement: after a successful `create_asset_counter`, the counter account has `data_len` exactly `SplAssetCounter::SIZE` (16), owner the shielded-pool program, discriminator exactly 6, and `next_id` exactly `FIRST_ASSET_ID` (2, since id 1 is reserved for native SOL).
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:41-55` (`fn process_create_asset_counter`), `program-libs/interface/src/state/spl_asset_counter.rs:34-41` (`fn init`)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit

- [x] **INV-CREATE-AC-07: re-initialization is impossible**
  - Covered by: `program-libs/interface/tests/state_props.rs` `init_rejects_reinitialization`
  - Kind: precondition
  - Statement: `create_asset_counter` on a counter whose discriminator byte is not 0 returns Err and leaves `next_id` unchanged (a second init cannot reset the id sequence).
  - Location: `program-libs/interface/src/state/spl_asset_counter.rs:35-37` (`fn init`)
  - Error: `ShieldedPoolError::SplAssetCounterAlreadyInitialized = 7026` (via `InterfaceError::AlreadyInitialized`)
  - Severity: Critical (asset-id reuse would alias distinct mints)
  - Suggested test: negative (call twice); harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [x] **INV-CREATE-AC-08: only the counter and authority lamports change**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_changes_only_the_counter_and_authority`
  - Kind: frame
  - Statement: after a successful `create_asset_counter`, every account other than the created counter and the authority (rent funding) has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:14-56`
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

## CreateSplInterface

### Authorization

- [x] **INV-CREATE-SPL-01: authority must sign**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_an_unsigned_authority`
  - Kind: precondition
  - Statement: `create_spl_interface` can only succeed when the first account (`authority`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:20` (`fn process_create_spl_interface`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-SPL-02: non-permissionless creation requires the protocol authority**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_unauthorized_caller`
  - Kind: precondition
  - Statement: when `protocol_config.spl_interface_creation_is_permissionless` is exactly 0, `create_spl_interface` returns Err for every signer whose address differs from `protocol_config.protocol_authority`.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:37-44` (`fn process_create_spl_interface`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative + positive (flag set); harness: mollusk unit

### Account Constraints

- [x] **INV-CREATE-SPL-03: system and token program accounts must be the expected programs**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_a_wrong_token_program`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the system-program account is not the system program or the token-program account is not the SPL Token program (`Tokenkeg...`).
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:29-35` (`fn process_create_spl_interface`)
  - Error: `ProgramError::IncorrectProgramId`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-SPL-04: registry and vault addresses must be the canonical per-mint PDAs**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_a_noncanonical_registry_pda`, `spl_interface_creation_rejects_a_noncanonical_vault_pda`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the registry address differs from the `[b"spl_asset_registry", mint]` PDA or the vault address differs from the `[b"spl_asset_vault", mint]` PDA; both bumps are derived canonically.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:48-57` (`fn process_create_spl_interface`)
  - Error: `ShieldedPoolError::InvalidPda = 7016`
  - Severity: Critical (vault identity)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-SPL-05: an existing registry blocks re-registration**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `duplicate_spl_interface_registration_is_rejected_without_consuming_id`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the registry account's `data_len` is not exactly 0 before creation, so a mint can be registered at most once.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:59-61` (`fn process_create_spl_interface`), `init.rs:22-27` (`fn RegistryInitParams::init`, zeroed-buffer check)
  - Error: `ShieldedPoolError::InvalidSplAssetRegistry = 7011`
  - Severity: Critical (asset-id aliasing)
  - Suggested test: negative (register twice); harness: program-tests integration (`cargo test-sbf`)

### Instruction Data Validation

- [x] **INV-CREATE-SPL-06: any payload byte is rejected**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_trailing_instruction_bytes`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the payload after the tag byte is non-empty.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:16-18` (`fn process_create_spl_interface`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### State Invariants

- [x] **INV-CREATE-SPL-07: the asset counter is strictly monotonic**
  - Covered by: `program-libs/interface/tests/state_props.rs` `counter_allocation_is_monotonic_and_bounded`
  - Kind: state
  - Statement: `allocate_id` hands out exactly the stored `next_id` and afterwards `next_id` is exactly the handed-out id plus 1; a counter with `next_id` strictly below 2 or at `u64::MAX` returns Err instead of allocating. Consequently no two successful `create_spl_interface` calls ever assign the same asset id.
  - Location: `program-libs/interface/src/state/spl_asset_counter.rs:46-55` (`fn allocate_id`), `create_spl_interface/processor.rs:63-71`
  - Error: `ShieldedPoolError::InvalidSplAssetRegistry = 7011`
  - Severity: Critical (asset-id uniqueness)
  - Suggested test: property (proptest over sequences) + positive; harness: `cargo test -p zolana-interface` + program-tests integration

- [x] **INV-CREATE-SPL-08: the counter must be initialized before use**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_a_cosplay_counter_account`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the counter account's discriminator byte is not exactly 6 (counter not yet created), or the counter account is not program-owned with `data_len` exactly 16.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:63-67`, `create_asset_counter.rs:64-77` (`fn load_spl_asset_counter_mut`)
  - Error: `ShieldedPoolError::InvalidSplAssetRegistry = 7011`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-CREATE-SPL-09: the registry record binds the mint to the allocated id**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_interface_registration_allocates_first_stable_id`
  - Kind: postcondition
  - Statement: after a successful `create_spl_interface`, the registry account has `data_len` exactly `SplAssetRegistry::SIZE` (48), discriminator exactly 5, `mint` exactly the supplied mint account's address, and `asset_id` exactly the id allocated from the counter in the same instruction.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:73-87` (`fn process_create_spl_interface`), `init.rs:14-32`
  - Severity: High
  - Suggested test: positive (full struct compare); harness: mollusk unit

- [x] **INV-CREATE-SPL-10: the vault is created as a token account owned by the CPI authority**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_interface_registration_allocates_first_stable_id`
  - Kind: postcondition
  - Statement: after a successful `create_spl_interface`, the vault account is owned by the SPL Token program, has `data_len` exactly 165, and is initialized via `InitializeAccount3` for the supplied mint with token-account owner exactly `SHIELDED_POOL_CPI_AUTHORITY`.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:89-105` (`fn process_create_spl_interface`), `init.rs:43-61` (`fn SplInterfaceInitParams::init`)
  - Severity: Critical (custody of all shielded tokens of that mint)
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-CREATE-SPL-11: counter next_id increases by exactly one**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_interface_registration_allocates_first_stable_id`
  - Kind: postcondition
  - Statement: after a successful `create_spl_interface`, the counter's `next_id` is exactly its value before plus 1.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:63-71`
  - Severity: High
  - Suggested test: positive; harness: mollusk unit

### Frame Conditions

- [x] **INV-CREATE-SPL-12: only registry, vault, counter, and authority lamports change**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_interface_creation_changes_only_the_expected_accounts`
  - Kind: frame
  - Statement: after a successful `create_spl_interface`, every account other than the created registry, the created vault, the counter (its `next_id`), and the authority (rent funding) has unchanged data and unchanged lamports; the mint account is read-only.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:15-105`
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit
