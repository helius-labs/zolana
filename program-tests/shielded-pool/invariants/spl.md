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
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:18` (`fn process_create_asset_counter`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-AC-02: only the protocol authority may create the counter**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_rejects_a_non_protocol_authority`
  - Kind: precondition
  - Statement: `create_asset_counter` returns Err for every signer whose address differs from `protocol_config.protocol_authority`; there is no permissionless flag for this instruction.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:27-32` (`fn process_create_asset_counter`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Account Constraints

- [x] **INV-CREATE-AC-03: system program account must be the system program**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_rejects_a_wrong_system_program`
  - Kind: precondition
  - Statement: `create_asset_counter` returns Err whenever the fourth account's address is not the system program id.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:23-25` (`fn process_create_asset_counter`)
  - Error: `ProgramError::IncorrectProgramId`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-AC-04: counter address must be the canonical counter PDA**
  - Covered by: `program-tests/shielded-pool/tests/admin/rejection.rs` `asset_counter_creation_rejects_a_non_canonical_pda`
  - Kind: precondition
  - Statement: `create_asset_counter` returns Err whenever the counter account's address differs from the PDA derived via `find_program_address([b"spl_asset_counter"])`; the canonical bump is derived, never supplied.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:34-38` (`fn process_create_asset_counter`)
  - Error: `ShieldedPoolError::InvalidPda = 7016`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Instruction Data Validation

- [x] **INV-CREATE-AC-05: any payload byte is rejected**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_rejects_trailing_instruction_bytes`
  - Kind: precondition
  - Statement: `create_asset_counter` returns Err whenever the payload after the tag byte is non-empty.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:14-16` (`fn process_create_asset_counter`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-CREATE-AC-06: the counter is initialized to the first asset id**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_initializes_complete_state`
  - Kind: postcondition
  - Statement: after a successful `create_asset_counter`, the counter account has `data_len` exactly `SplAssetCounter::SIZE` (16), owner the shielded-pool program, discriminator exactly 6, and `next_id` exactly `FIRST_ASSET_ID` (2, since id 1 is reserved for native SOL).
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:40-53` (`fn process_create_asset_counter`), `program-libs/interface/src/state/spl_asset_counter.rs:34-41` (`fn init`)
  - Severity: High
  - Suggested test: positive; harness: mollusk unit

- [~] **INV-CREATE-AC-07: re-initialization is impossible**
  - Cross-branch coverage: the init guard and its tests live on the security/spp-config-init-gate branch, landing before this one — the `init_rejects_reinitialization` case in that branch's `program-libs/interface/tests/state_props.rs` (on THIS branch the guard is reverted out: `init()` takes no error path)
  - Kind: precondition
  - Statement: `create_asset_counter` on a counter whose discriminator byte is not 0 returns Err and leaves `next_id` unchanged (a second init cannot reset the id sequence).
  - Location: `program-libs/interface/src/state/spl_asset_counter.rs:35-37` (`fn init`)
  - Error: `ShieldedPoolError::SplAssetCounterAlreadyInitialized = 7045` (via `InterfaceError::AlreadyInitialized`, `program-libs/interface/src/error.rs:135-137`)
  - Severity: Critical (asset-id reuse would alias distinct mints)
  - Suggested test: negative (call twice); harness: program-tests integration (`cargo test-sbf`)

### Frame Conditions

- [x] **INV-CREATE-AC-08: only the counter and authority lamports change**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/contract.rs` `asset_counter_creation_changes_only_the_counter_and_authority`
  - Kind: frame
  - Statement: after a successful `create_asset_counter`, every account other than the created counter and the authority (rent funding) has unchanged data and unchanged lamports.
  - Location: `programs/shielded-pool/src/instructions/create_asset_counter.rs:13-55`
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

## CreateSplInterface

### Authorization

- [x] **INV-CREATE-SPL-01: authority must sign**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_an_unsigned_authority`
  - Kind: precondition
  - Statement: `create_spl_interface` can only succeed when the first account (`authority`) is a signer.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:22` (`fn process_create_spl_interface`)
  - Error: account-checks signer error
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-SPL-02: non-permissionless creation requires the protocol authority**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_unauthorized_caller`
  - Kind: precondition
  - Statement: when `protocol_config.spl_interface_creation_is_permissionless` is exactly 0, `create_spl_interface` returns Err for every signer whose address differs from `protocol_config.protocol_authority`.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:41-46` (`fn process_create_spl_interface`)
  - Error: `ShieldedPoolError::UnauthorizedCaller = 7003`
  - Severity: High
  - Suggested test: negative + positive (flag set); harness: mollusk unit

### Account Constraints

- [x] **INV-CREATE-SPL-03: system and token program accounts must be the expected programs**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_a_wrong_token_program`, `spl_interface_creation_rejects_a_wrong_system_program`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the system-program account is not the system program, or the token-program account is neither the SPL Token program (`Tokenkeg...`) nor the Token-2022 program (Token-2022 mints are accepted; see INV-CREATE-SPL-13).
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:35-37` (system-program check), `create_spl_interface/validate.rs:26-32` (token-program check)
  - Error: `ProgramError::IncorrectProgramId` (wrong system-program account only); `ShieldedPoolError::UnsupportedSplTokenProgram = 7041` (wrong token-program account)
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-SPL-04: registry and vault addresses must be the canonical per-mint PDAs**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_a_noncanonical_registry_pda`, `spl_interface_creation_rejects_a_noncanonical_vault_pda`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the registry address differs from the `[b"spl_asset_registry", mint]` PDA or the vault address differs from the `[b"spl_asset_vault", mint]` PDA; both bumps are derived canonically.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:62-66, 88-92` (`fn process_create_spl_interface`)
  - Error: `ShieldedPoolError::InvalidPda = 7016`
  - Severity: Critical (vault identity)
  - Suggested test: negative; harness: mollusk unit

- [x] **INV-CREATE-SPL-05: an existing registry blocks re-registration**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `duplicate_spl_interface_registration_is_rejected_without_consuming_id`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the registry account's `data_len` is not exactly 0 before creation, so a mint can be registered at most once.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:67-69` (`fn process_create_spl_interface`), `init.rs:25-27` (`fn RegistryInitParams::init`, zeroed-buffer check)
  - Error: `ShieldedPoolError::InvalidSplAssetRegistry = 7011`
  - Severity: Critical (asset-id aliasing)
  - Suggested test: negative (register twice); harness: program-tests integration (`cargo test-sbf`)

### Instruction Data Validation

- [x] **INV-CREATE-SPL-06: any payload byte is rejected**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_trailing_instruction_bytes`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the payload after the tag byte is non-empty.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:18-20` (`fn process_create_spl_interface`)
  - Error: `ShieldedPoolError::InvalidInstructionData = 7000`
  - Severity: Medium
  - Suggested test: negative; harness: mollusk unit

### State Invariants

- [x] **INV-CREATE-SPL-07: the asset counter is strictly monotonic**
  - Covered by: `program-libs/interface/tests/state_props.rs` `counter_allocation_is_monotonic_and_bounded`
  - Kind: state
  - Statement: `allocate_id` hands out exactly the stored `next_id` and afterwards `next_id` is exactly the handed-out id plus 1; a counter with `next_id` strictly below 2 or at `u64::MAX` returns Err instead of allocating. Consequently no two successful `create_spl_interface` calls ever assign the same asset id.
  - Location: `program-libs/interface/src/state/spl_asset_counter.rs:46-55` (`fn allocate_id`), `create_spl_interface/processor.rs:51-59`
  - Error: `ShieldedPoolError::InvalidSplAssetRegistry = 7011`
  - Severity: Critical (asset-id uniqueness)
  - Suggested test: property (proptest over sequences) + positive; harness: `cargo test -p zolana-interface` + program-tests integration

- [x] **INV-CREATE-SPL-08: the counter must be initialized before use**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_a_cosplay_counter_account`
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the counter account's discriminator byte is not exactly 6 (counter not yet created), or the counter account is not program-owned with `data_len` exactly 16.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:52-55`, `create_asset_counter.rs:63-70` (`fn load_spl_asset_counter_mut`)
  - Error: `ShieldedPoolError::InvalidSplAssetRegistry = 7011`
  - Severity: High
  - Suggested test: negative; harness: mollusk unit

### Success Postconditions

- [x] **INV-CREATE-SPL-09: the registry record binds the mint to the allocated id**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_interface_registration_allocates_first_stable_id`
  - Kind: postcondition
  - Statement: after a successful `create_spl_interface`, the registry account has `data_len` exactly `SplAssetRegistry::SIZE` (48), discriminator exactly 5, `mint` exactly the supplied mint account's address, and `asset_id` exactly the id allocated from the counter in the same instruction.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:60-85` (`fn process_create_spl_interface`), `init.rs:14-32`
  - Severity: High
  - Suggested test: positive (full struct compare); harness: mollusk unit

- [x] **INV-CREATE-SPL-10: the vault is created as a token account owned by the CPI authority**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_interface_registration_allocates_first_stable_id`
  - Kind: postcondition
  - Statement: after a successful `create_spl_interface`, the vault account is owned by the validated token program (SPL Token or Token-2022), has `data_len` exactly `validated_mint.token_account_len` (exactly 165 for SPL Token; for Token-2022 computed via `try_calculate_account_len` from the mint's required account extensions), and is initialized via `InitializeAccount3` for the supplied mint with token-account owner exactly `SHIELDED_POOL_CPI_AUTHORITY`.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:87-112` (`fn process_create_spl_interface`), `init.rs:43-60` (`fn SplInterfaceInitParams::init`)
  - Severity: Critical (custody of all shielded tokens of that mint)
  - Suggested test: positive; harness: program-tests integration (`cargo test-sbf`)

- [x] **INV-CREATE-SPL-11: counter next_id increases by exactly one**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_interface_registration_allocates_first_stable_id`
  - Kind: postcondition
  - Statement: after a successful `create_spl_interface`, the counter's `next_id` is exactly its value before plus 1.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:51-59`
  - Severity: High
  - Suggested test: positive; harness: mollusk unit

### Frame Conditions

- [x] **INV-CREATE-SPL-12: only registry, vault, counter, and authority lamports change**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/functional.rs` `spl_interface_creation_changes_only_the_expected_accounts`
  - Kind: frame
  - Statement: after a successful `create_spl_interface`, every account other than the created registry, the created vault, the counter (its `next_id`), and the authority (rent funding) has unchanged data and unchanged lamports; the mint account is read-only.
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:17-112`
  - Severity: Medium
  - Suggested test: positive; harness: mollusk unit

### Token-2022 Support

- [x] **INV-CREATE-SPL-13: Token-2022 mints are supported with an extension allow-list**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/validation.rs` (`accepts_safe_token_2022_mint_extensions`, `sizes_vault_for_transfer_fee_accounts`, `accepts_confidential_token_extensions`, `rejects_unsupported_token_2022_extensions` → 7043), `program-tests/shielded-pool/tests/spl_interface/functional.rs` `token_2022_interface_and_proofless_deposit_settle` (positive), `spl_interface/rejection.rs` `spl_interface_creation_rejects_a_mint_not_owned_by_the_token_program` (7042 mint-ownership branch), `spl_interface_creation_rejects_an_spl_token_mint_with_a_wrong_length` and `spl_interface_creation_rejects_an_uninitialized_spl_token_mint` (7042 SPL-Token layout/flag), `spl_interface_creation_rejects_a_truncated_token_2022_mint` (7042 Token-2022 unpack), `spl_interface_creation_rejects_an_uninitialized_token_2022_mint` (7042 Token-2022 uninitialized — the :54-55 re-check is shadowed by the pod unpack's own check, documented in the test), `spl_interface_creation_rejects_a_token_2022_mint_with_malformed_tlv_data` (7042 extension-types query)
  - Kind: precondition
  - Statement: the `token_program` account must be the SPL Token or Token-2022 program (else 7041); the mint must be owned by that program and initialized — the exact 82-byte layout with the initialized flag set for SPL Token, `PodStateWithExtensions<PodMint>` with `is_initialized` for Token-2022 (else 7042); every mint extension must be in the 13-entry allow-list (`is_allowed_mint_extension`, else 7043); the vault is then allocated at `try_calculate_account_len` of the mint's required account extensions (see INV-CREATE-SPL-10).
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/validate.rs:22-89` (`fn validate_token_mint_for_interface`, `fn is_allowed_mint_extension`), `create_spl_interface/processor.rs:38, 99`
  - Error: `ShieldedPoolError::UnsupportedSplTokenProgram = 7041` / `ShieldedPoolError::InvalidSplTokenMint = 7042` / `ShieldedPoolError::UnsupportedToken2022Extension = 7043`
  - Severity: Critical (custody of all shielded tokens of the mint)
  - Suggested test: none remaining (every reachable 7042 branch is pinned; the mint-borrow-failure branch at :39 is unfixable from outside an instruction and the `try_calculate_account_len` failure at :66 is unreachable after the :60 allow-list filter — both documented in the rejection suite)

- [x] **INV-CREATE-SPL-14: a pre-existing vault account blocks creation**
  - Covered by: `program-tests/shielded-pool/tests/spl_interface/rejection.rs` `spl_interface_creation_rejects_a_pre_existing_vault_account` (the registry-side mirror is covered by `duplicate_spl_interface_registration_is_rejected_without_consuming_id`).
  - Kind: precondition
  - Statement: `create_spl_interface` returns Err whenever the vault account's `data_len` is not exactly 0 before creation (mirrors INV-CREATE-SPL-05 for the registry).
  - Location: `programs/shielded-pool/src/instructions/create_spl_interface/processor.rs:93-95` (`fn process_create_spl_interface`)
  - Error: `ShieldedPoolError::InvalidSplAssetRegistry = 7011`
  - Severity: Medium
  - Suggested test: negative (pre-allocate the vault PDA); harness: program-tests integration (`cargo test-sbf`)
