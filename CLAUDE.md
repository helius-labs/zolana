# Confidential Transfers

Confidential transfer Solana program using Groth16 ZK proofs with pinocchio 0.10.
Circuits are written in gnark (Go); the Rust SDK proves them via the
`prover` cgo bridge.

The trusted-setup output (`pk.bin`, `vk.bin`) and the matching Rust VK
constants under `interface/src/verifying_keys/*.rs` are committed.
Regenerate them with `just build-circuit <name>` only when keys need
to be rotated.

## Build and Test Commands

```bash
# Run gnark trusted setup for one circuit and regenerate the matching
# interface/src/verifying_keys/<circuit>.rs file. Run only when keys
# need to be rotated -- the current pk/vk pairs are committed to git.
just build-circuit transfer        # or batchtransfer | encryption

# Run gnark setup for every production circuit
just build-circuits

# Build SBF binary
cargo build-sbf --manifest-path programs/confidential_transfers/Cargo.toml  # or: just build-program

# Build everything (program only -- circuits are pre-built and committed)
just build

# Type-check program
cargo check -p confidential-transfers

# Run integration tests
cargo test-sbf -p confidential-transfers-tests --test <name>  # or: just test <name>

# Debug a specific test
RUST_BACKTRACE=1 cargo test-sbf -p confidential-transfers-tests --test <name> -- --test <test_fn> --nocapture 2>&1 | tail -500

# Format all Rust code
just format

# Check formatting and run clippy
just lint

# CU benchmarks -- regenerates CU_BENCHMARK.md
just bench

# Proving benchmarks -- regenerates PROVING_BENCHMARK.md (Groth16 wall-clock times per circuit)
just bench-proving
```

### CU Profiling

Results are in [`CU_BENCHMARK.md`](CU_BENCHMARK.md). The `bench` feature instruments all parse/process functions with `#[profile]` from `light-program-profiler`, which uses custom syscalls (`sol_log_compute_units_start/end`) not in the standard Solana runtime. The `[patch.crates-io]` section in `Cargo.toml` patches several Agave crates from `Lightprotocol/agave` branch `jorrit/profiling-runtime-v3.1` to add these syscalls to `solana-program-runtime`. Without the patches litesvm cannot handle the profiler syscalls and the program fails at runtime.

#### CU bench variance from `find_program_address`

CU benches for instructions that derive a canonical PDA bump can swing by ~1500 CU per bump iteration between runs. `Address::find_program_address` (called via `verify_pda` in `programs/confidential_transfers/src/shared/create_pda.rs:90`) starts at bump 255 and decrements until it finds a valid PDA -- each failed iteration costs ~1500 CU. The bump value depends on the runtime addresses of the seeds (test keypairs, mint, owner, etc.), so reordering tests, changing the binary, or any seed change can shift bumps and produce apparent ±1500/3000/4500 CU regressions or improvements that are pure noise, not real changes.

When reviewing a `just bench` diff, ignore deltas in these instructions unless they substantially exceed the bump-search variance:

| Instruction                       | Function                                       | File                                                                             |
| --------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------------------- |
| Create Program Config             | `process_create_program_config_ix`             | `program_config/create.rs:40`                                                    |
| Create Token Pool                 | `process_create_token_pool_ix` (2 PDAs)        | `create_token_pool.rs:54,62`                                                     |
| Create Confidential Config        | `process_create_confidential_config_ix`        | `config_account/create/processor.rs:51`                                          |
| Create Config Token Account       | `process_create_config_token_account_ix`       | `config_token_account/create/processor.rs:58`                                    |
| Create Associated Token Account   | `process_create_ata_ix` (+ optional 2nd lookup) | `associated_token_account/create/processor.rs:63,138`                            |
| Create Key Update Proposal        | `process_create_key_update_proposal_ix`        | `key_update/create_proposal/processor.rs:62`                                     |
| Create Buffer                     | `process_create_buffer_ix`                     | `batch_execution/create_buffer.rs:44`                                            |
| Create Proposal Buffer            | `process_create_proposal_buffer_ix`            | `async_execution/create_proposal_buffer/processor.rs:52`                         |
| Remove From Buffer                | `process_remove_from_buffer_ix`                | `batch_execution/remove_from_buffer/processor.rs:112`                            |
| Sync Withdrawal                   | `process_sync_withdrawal_ix` (cpi_authority)   | `sync/withdrawal.rs:52`                                                          |
| Async Withdrawal                  | `process_async_withdrawal_ix` (cpi_authority)  | `async_execution/withdrawal.rs:52`                                               |
| Clear Text Withdrawal             | `process_clear_text_withdrawal_ix` (cpi_authority) | `escape/clear_text_withdrawal.rs:52`                                         |

## Project Structure

```
circuits/              -- gnark circuit sources (Go)
  main.go              -- cgo entrypoint (Setup, Prove, ...)
  go.mod               -- module circuits
  transfer/            -- ConfidentialTransfer circuit
  batchtransfer/       -- BatchTransfer(N=25) circuit
  encryption/          -- UnifiedEncryption circuit
  poseidon/            -- in-circuit Poseidon gadget (iden3 constants via go:linkname)
prover/                -- gnark BN254 Groth16 Rust crate
  src/lib.rs           -- shared helpers (HashedAddress, PublicInputs, ...) + ffi re-exports
  src/ffi.rs           -- cgo bridge (Setup, Prove, CircuitId, ProveOutput)
  src/{transfer,deposit,withdrawal,batch_transfer,encryption}.rs -- per-circuit ProofInputs/Prover
  src/vk_codegen.rs    -- gnark vk.bin -> Rust source codegen
  src/bin/setup.rs     -- `prover-setup` CLI (Setup + write Rust VK file)
  build.rs             -- go mod tidy + go build c-archive + bindgen
build/gnark/<circuit>/ -- pk.bin, vk.bin produced by `prover-setup`
interface/src/         -- shared types, state structs, instruction builders, error enum
  lib.rs               -- re-exports modules
  constants.rs         -- PROGRAM_ID, SPL_TOKEN_PROGRAM_ID as Pubkey
  error.rs             -- ConfidentialTransferError enum (thiserror, #[repr(u32)])
  state/
    mod.rs
    discriminator.rs   -- 1-byte account type constants
    <account>.rs       -- Pod/Zeroable structs with from_account_info_checked + init
  instruction/
    builders/          -- one builder struct per instruction (e.g. Transfer, Deposit)
    instruction_data/  -- borsh-serializable instruction data types
  verifying_keys/      -- committed VK constants (regenerated by `just build-circuit <name>`)
sdk/src/               -- client SDK: encryption, constants, proposal builders
  constants.rs         -- PROGRAM_ID (as Address and Pubkey)
  encryption.rs        -- encryption utilities
  proposal.rs          -- stateless proposal builders (uses prover crate)
test-utils/src/        -- test helpers shared across integration tests
  setup.rs             -- create_program_config, setup_rpc, serialize_token_account
  backend/             -- Backend struct simulating the server-side role
  asserts/             -- per-instruction assertion helpers (e.g. assert_transfer)
  spl.rs, multisig.rs, smart_account.rs, encryption.rs -- specialized test utils
api/                   -- Backend API specification
  openapi.yaml         -- OpenAPI 3.0.3 spec (JSON-RPC 2.0 endpoints)
  README.md            -- auto-generated endpoint reference
  generate-readme.sh   -- regenerates README.md from openapi.yaml
CU_BENCHMARK.md        -- auto-generated CU profiling results (see bench test)
programs/confidential_transfers/src/
  lib.rs               -- entrypoint + instruction dispatch (tag 0-N)
  error.rs             -- re-exports interface error + From<> for ProgramError impl
  create_pda.rs        -- create_pda_account + verify_pda helpers
  loaders.rs           -- account deserialization/validation helpers
  shared.rs            -- shared processor utilities
  sync/                -- synchronous instructions (transfer/, deposit/, withdrawal/)
  async_execution/     -- async instructions (create_proposal/, transfer/, deposit/, etc.)
  config_account/      -- confidential config lifecycle (create/, migrate/, close/)
  config_token_account/ -- config token account lifecycle (create/, migrate/, close/)
  associated_token_account/ -- associated token account lifecycle (create/, migrate/, close/)
  key_update/          -- encryption key updates (execute/, create_proposal/, cancel_proposal/)
  program_config/      -- program config instructions (create/, update_config/, update_authority/)
  create_token_pool/   -- token pool creation instruction
  <instruction_name>/
    mod.rs             -- wires submodules together
    processor.rs       -- parsing, validation, and business logic
    init.rs            -- account initialization helpers (optional)
    verify.rs          -- proof/data verification (optional)
    apply.rs           -- state mutations during migrations (optional)
programs/confidential_transfers/tests/
  sync/                -- synchronous operation tests (transfer, deposit, withdrawal, e2e)
  async_execution/     -- async operation tests (create_proposal, transfer, e2e, etc.)
  smart_account/       -- smart account tests (setup, account, async, sync)
  program_config/      -- program config tests (create, update_config, update_authority)
  token_account/       -- token account tests (create_ata, create_config)
  token_pool.rs        -- token pool tests
  account_encryption.rs -- account encryption tests
Cargo.toml             -- workspace root, [[test]] entries, workspace deps
```

## Pinocchio 0.10 API

This project uses pinocchio, not Anchor. Key types and idioms:

- `AccountView` (not AccountInfo), `Address` (not Pubkey)
- `account.owned_by(&address)`, `account.is_signer()`, `account.address()`
- `account.try_borrow()` -> `Ref<[u8]>`, `account.try_borrow_mut()` -> `RefMut<[u8]>`
- `Ref::map(data, |d| bytemuck::from_bytes(d))` for zero-copy deserialization
- `Address::find_program_address(seeds, program_id)` -- only on Solana target, needs cfg gate
- `pinocchio::cpi::{Seed, Signer}` -- CPI signing (requires `cpi` feature)
- `pinocchio_system::create_account_with_minimum_balance_signed` -- handles both hot/cold path
- `pinocchio_system::check_id(address)` -- verify system program

## Instruction Module Pattern

**Simple instructions** (close, toggle, single-file):
- Single `.rs` file with `process_<name>_ix` containing parsing, validation, and logic inline
- `#[inline(always)]` for small functions, `#[inline(never)]` for larger ones

**Complex instructions** (create, migrate, execute):
- `mod.rs` -- declares submodules, exports `process_<name>_ix`
- `processor.rs` -- `process_<name>_ix` entry point with inline parsing/validation and business logic
- `init.rs` -- account initialization helpers (optional)
- `verify.rs` -- proof/data verification (optional)
- `apply.rs` -- state mutations during migrations (optional)

**Common structure in processor.rs:**
- Check `accounts.len() >= N`
- Validate signers, system program, PDA derivation (for creation only)
- Parse instruction data via `zero_copy_at()` or manual slicing
- Define `<Name>Accounts` struct for validated account references
- Call state helpers (`create_pda_account`, `State::init`, etc.)

**lib.rs dispatch:**
- Add `pub mod <instruction_name>;` + `use` import
- Add new tag to match: `N => process_<name>_ix(program_id, accounts, data),`

## State Struct Pattern

State structs live in `interface/src/state/`. Reference: `ProgramConfig`

```rust
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct MyState {
    pub discriminator: u8,       // first byte, from interface::state::discriminator constants
    pub field1: [u8; 32],
    pub bump: u8,
}
```

Required methods:
- `const SIZE: usize = core::mem::size_of::<Self>()`
- `const SEED: &[u8] = b"my_seed"` (for PDA-based accounts)
- `from_account_info_checked(account, program_id) -> Result<Ref<Self>, ProgramError>` -- validates owner + length + discriminator
- `init(account, ..fields, bump) -> Result<(), ProgramError>` -- checks `data[0] == 0`, writes discriminator + fields via bytemuck

Add discriminator constant to `interface/src/state/discriminator.rs`.

## Error Pattern

The error enum is defined in `interface/src/error.rs` (shared across crates):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[repr(u32)]
pub enum ConfidentialTransferError {
    #[error("Description")]
    Variant = N,
}
```

The program crate (`programs/confidential_transfers/src/error.rs`) duplicates the enum and adds the `From<> for ProgramError` impl (needed because `ProgramError` is from pinocchio, which is not a dependency of the interface crate):

```rust
impl From<ConfidentialTransferError> for ProgramError {
    fn from(e: ConfidentialTransferError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
```

## PDA Helpers

Located in `programs/confidential_transfers/src/create_pda.rs`:

- `create_pda_account(fee_payer, new_account, space, owner, signer_seeds, bump)` -- delegates to `pinocchio_system::create_account_with_minimum_balance_signed`, handles hot path (lamports==0) and cold path (attacker donated lamports). Uses match-on-length for Seed arrays (1/2/3 seeds).
- `verify_pda(account_key, seeds, program_id) -> Result<u8, ProgramError>` -- cfg-gated: uses `Address::find_program_address` on Solana target, `unimplemented!()` on host.

## Instruction Builder Pattern (interface crate)

Builders live in `interface/src/instruction/builders/`. Reference: `create_token_pool.rs`

```rust
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use crate::constants::{PROGRAM_ID_PUBKEY, SPL_TOKEN_PROGRAM_ID_PUBKEY};

pub struct CreateTokenPool {
    pub fee_payer: Pubkey,
    pub token_pool_pda: Pubkey,
    pub mint: Pubkey,
    pub cpi_authority_pda: Pubkey,
}

impl CreateTokenPool {
    pub fn instruction(&self) -> Instruction {
        let data = [6u8];
        Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![
                AccountMeta::new(self.fee_payer, true),
                AccountMeta::new(self.token_pool_pda, false),
                // ...
            ],
            data: data.to_vec(),
        }
    }
}
```

- Use `PROGRAM_ID_PUBKEY` from `interface/src/constants.rs`, do not pass as parameter
- Use fixed-size arrays for instruction data, not Vec
- Add `pub mod <name>;` + `pub use <name>::<Struct>;` to `interface/src/instruction/builders/mod.rs`
- Builders are imported in tests as `confidential_token_interface::instruction::CreateTokenPool`

## Integration Test Pattern

Reference: `tests/sync/transfer.rs`

```rust
use confidential_token_interface::{
    error::ConfidentialTransferError,
    instruction::Transfer,
    state::config_token_account::ConfigTokenAccount,
};
use sdk::constants::PROGRAM_ID;
use test_utils::{
    asserts::transfer::assert_transfer,
    setup::{create_program_config, setup_rpc},
    backend::Backend,
};
use light_program_test::{LightProgramTest, Rpc};
use light_program_test::utils::assert::assert_rpc_error;
```

- Tests are organized in subdirectories: `sync/`, `async_execution/`, `smart_account/`, `program_config/`, `token_account/`
- Setup: `setup_rpc()` from `test_utils::setup`, returns `LightProgramTest`
- Success assertion: use per-instruction assert helpers from `test_utils::asserts::*`
- Error assertion: `assert_rpc_error(result, ix_index, ConfidentialTransferError::Variant as u32).expect("...")`
- Add `[[test]] name = "<name>" path = "tests/<subdir>/<name>.rs"` to root `Cargo.toml`
- Debug: `RUST_BACKTRACE=1 cargo test-sbf ... -- --nocapture 2>&1 | tail -500`

## Circuit Build Pipeline

Circuits are gnark BN254 Groth16, written in Go and proved via cgo.
The pipeline:

1. **Source**: `circuits/<name>/<name>.go` defines the `Circuit`
   struct (typed witness signals) and `Define` (constraints). The
   in-circuit Poseidon gadget at `circuits/poseidon/` reads BN254
   round constants directly from
   `github.com/iden3/go-iden3-crypto/poseidon` via `go:linkname` so
   the hashes match `light_hasher::Poseidon` byte-for-byte.

2. **Setup**: `cargo run -p prover --bin prover-setup -- <circuit>
   build/gnark/<circuit>` (or `just build-circuit <circuit>`) compiles
   the circuit, runs `groth16.Setup`, writes `pk.bin` + `vk.bin` to
   `build/gnark/<circuit>/`, parses `vk.bin` via the gnark-crypto
   uncompressed-BE layout, and emits a Rust `Groth16Verifyingkey`
   constant directly into `interface/src/verifying_keys/<circuit>.rs`.

3. **Proving**: the per-circuit provers (`prover/src/{transfer,deposit,
   withdrawal,batch_transfer,encryption}.rs`) build a witness map and
   call `prover::prove(CircuitId::*, &witness_map)`, then convert the
   gnark proof bytes to wire format via `gnark_proof_to_wire` (negate
   `proof_a`, compress G1/G2 with `solana_bn254::compression`).

4. **Verification**: on-chain verifier in
   `programs/confidential_transfers/src/shared/verify_transfer.rs`
   uses `groth16-solana`'s `Groth16Verifier` against the committed
   `interface/src/verifying_keys/*.rs` constants. No build-time
   regeneration -- the constants are committed source files.

Artifacts in `build/gnark/<circuit>/`: `pk.bin`, `vk.bin` (both gnark
binary, used for prover/verifier loading and Rust VK codegen).

## Backend API Specification

The Backend's public interface is documented as an OpenAPI 3.0.3 spec in `api/openapi.yaml`. Each endpoint uses JSON-RPC 2.0 envelopes (one `POST` path per method). The `test-utils/src/backend/` struct implements these methods.

### Files

- `api/openapi.yaml` -- source of truth
- `api/README.md` -- auto-generated endpoint reference (do not edit manually)
- `api/generate-readme.sh` -- regenerates README from the spec (`./api/generate-readme.sh`)
- `.claude/api-style-guide.md` -- description style rules for endpoint descriptions

### Endpoint Categories

| Category | Endpoints | Description |
|----------|-----------|-------------|
| Account lookup | getTokenAccount, getConfigAccount, getProposal, getProposals | Read and decrypt accounts/proposals |
| Account creation | requestCreateUserAccount, requestCreateConfigAccount, buildCreateConfigIx | Create confidential token accounts |
| Async operations | buildAsyncDepositExecutionIx, buildAsyncTransferExecutionIx, buildAsyncWithdrawalExecutionIx | Two-phase proposal execution |
| Sync operations | requestSyncDeposit, requestSyncTransfer, requestSyncWithdrawal, buildSyncDepositIx, buildSyncTransferIx, buildSyncWithdrawalIx | Single-step operations |
| Transaction signing | coSign | Co-sign transactions with program authority |

### Signer Mode Tags

Endpoints are tagged by signer mode:
- **(Keypair)** -- account owner is a regular keypair; client provides ed25519 signatures or signs the transaction; backend builds, signs, and sends
- **(Smart account)** -- account owner is a PDA; returns instructions for the caller to wrap and submit via CPI
- Untagged endpoints work with both modes

### Conventions

- Method names use camelCase (e.g. `getTokenAccount`)
- Backend Rust methods use snake_case (e.g. `get_token_account`)
- Descriptions follow `.claude/api-style-guide.md`
- After editing `openapi.yaml`, regenerate the README: `./api/generate-readme.sh`
- all public functions in shared/ must be used in multiple dirs

### Instruction data
1. default light-zero-copy
3. if not hot path can use borsh

### wincode length prefixes (zolana-transaction)

When choosing the length encoding for a wincode `containers::Vec<T, FixIntLen<..>>`:
- `Vec<u8>` (byte vectors: ciphertexts, program/zone data, can exceed 255 bytes) use `FixIntLen<u16>`.
- every other vector (element counts: records, recipient slots, recipient viewing keys; always small) use `FixIntLen<u8>`.

Rule of thumb: `Vec<u8>` -> `u16`, otherwise -> `u8`.

### Accounts
1. if lamports are transferred accounts must have fee payer account else must not have a fee payer account
2. no need to verify pda derivation for initialized accounts, checking discriminator and program ownership is enough if access control checks dont rely on the derivation itself, if access control relies on the derivation check store the bump in the account data or send it in instruction data, account data is cleaner if the account has data
3. Every account that is read or written to must be accessed with a load prefixed function that is defined in a a loader.rs file
4. PDA creation must use canonical bumps derived via `find_program_address` (verify_pda), never accept bumps from instruction data for account creation
5. init pattern:
    - must use a param struct with an init method `pub fn init(self, account: &AccountView) -> ProgramResult {`
    - must check that account is not already initialized
    - no program id necessary the svm will not allow to write to an account owned by another program
    - all account struct fields must be initialized
    - account size must match the account struct size exactly
6. Recovery and owner encryption keys
    - the owner needs to sign to add or remove encryption keys other than auditor keys
7. all signer checks must be in the processor not nested inside of other functions
8. closing accounts
    - every account close instruction must have a dedicated rent_recipient

## Crate hierachy

1. the program must only depend on the interface crate and possibly other low level crates that pull in as few dependencies as possible it must not depend on its own sdks
2. sdks must not depend on test-utils not in deps or dev-deps

## Proof generation for tests
1. Loading proving keys for big circuits takes a lot of time
2. tests should start a prover server if not started yet
3. The prover server should be lazy it should not load any proving keys on startup it should load them when a proof for that key is requested and then keep it loaded so that the key doesnt need to be loaded again‚
