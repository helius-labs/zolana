# Zolana Contributor Notes

## Source Of Truth

`docs/spec.md` is the protocol source of truth. Do not edit it as part of
implementation cleanup unless that is the explicit task. If code, tests, and the
spec disagree, treat the code or tests as suspect first.

## Repo Structure

program-libs
- libraries used in programs
- are publised as crates

programs
- must not depend on sdk libs
- are not published as crates

program-tests
- integration test (programs) for programs 
- are not publised as crates

sdk-libs
- libraries to interact with programs

sdk-tests
- integration test programs for sdks

prover
- go circuits
- go prover server
- rust prover client

## Workspace Shape

- `programs/shielded-pool`: on-chain SPP program.
- `program-libs/interface`: shared instruction data, tags, constants, and layout
  helpers.
- `program-tests`: internal test crates and test-only SBF programs.
- `sdk-libs`: externally useful Rust SDK crates.
- `cli`: local developer/operator tooling.
- `forester`: compileable forester skeleton for future nullifier-tree
  maintenance work.
- `prover`: proof client and prover server.

## Project Structure

```text
programs/shielded-pool/src/
  lib.rs               -- entrypoint
  processor.rs         -- instruction dispatch by tag
  error.rs             -- program error conversions
  instructions/
    loader.rs          -- account loading and shared account validation
    <instruction>/
      mod.rs           -- wires processor/verify/init helpers together
      processor.rs     -- signer checks, parsing handoff, business flow
      verify.rs        -- account/data verification for that instruction
      init.rs          -- account initialization helpers when needed

program-libs/interface/src/
  lib.rs               -- canonical program ids and public modules
  instruction/
    tag.rs             -- first-byte instruction tags
    builders/          -- client instruction builders
    instruction_data/  -- Borsh or fixed-layout instruction data structs
  state/               -- client-visible account headers and discriminators
  verifying_keys/      -- verifier constants when proof paths need them

program-tests/
  shielded-pool/       -- internal litesvm/localnet tests

sdk-libs/
  keypair/             -- shielded key material and hashes
  program-test/        -- reusable local test/indexer harness
  transaction/         -- wallet, UTXO, encryption, and transaction logic

cli/                   -- root Zolana developer/operator CLI
forester/              -- forester skeleton
prover/                -- Rust prover client and Go prover server
xtask/                 -- workspace maintenance tools
```

## Common Commands

Use `just` recipes for normal workflows:

```bash
just check-all
just test-shielded-pool
just test-sdk-libs
just test-litesvm
just test-cli
just clippy
```

Program tests that load real SBF binaries need the local builds:

```bash
just build-programs
```

## Code Style

- Keep protocol math in one canonical implementation and reuse it from tests.
- Keep public SDK surface deliberate; test-only helpers belong under
  `program-tests` unless they are useful to external developers.
- Avoid compatibility shims for removed Light/legacy surfaces.
- Prefer small, explicit helpers over broad abstractions.
- Comments should explain invariants, security constraints, or non-obvious
  layout decisions. Remove comments that only narrate the code.

## Pinocchio 0.11 API

This project uses Pinocchio, not Anchor. Key types and idioms:

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

State structs live in `program-libs/interface/src/state/`. Reference:
`ShieldedPoolConfig`.

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

Add discriminator constant to `program-libs/interface/src/state/discriminator.rs`.

## Error Pattern

The error enum is defined in `programs/shielded-pool/src/error.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[repr(u32)]
pub enum ShieldedPoolError {
    #[error("Description")]
    Variant = N,
}
```

The program crate adds the `From<> for ProgramError` impl (needed because
`ProgramError` is from Pinocchio):

```rust
impl From<ShieldedPoolError> for ProgramError {
    fn from(e: ShieldedPoolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
```

If an error enum is shared with clients, define the shared shape in the
interface crate and keep the `ProgramError` conversion in the program crate.
Once an error code is observable by tests or clients, do not renumber it
casually.

## PDA Helpers

- Account creation helpers should delegate to the Pinocchio system helpers,
  handle both hot path (`lamports == 0`) and cold path (attacker donated
  lamports), and keep signer seed handling local to the creation path.
- `verify_pda(account_key, seeds, program_id) -> Result<u8, ProgramError>` must
  be cfg-gated: use `Address::find_program_address` on Solana target and do not
  pretend host tests can derive it unless a host implementation exists.

## Instruction Builder Pattern (interface crate)

Builders live in `program-libs/interface/src/instruction/builders/`. Reference:
`create_pool_tree.rs`

```rust
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use crate::{instruction::{tag, CreatePoolTreeData}, SHIELDED_POOL_PROGRAM_ID};

pub fn create_pool_tree(payer: Pubkey, tree: Pubkey, data: CreatePoolTreeData) -> Instruction {
    let mut instruction_data = vec![tag::CREATE_POOL_TREE];
    data.serialize(&mut instruction_data)
        .expect("shielded-pool instruction serialization is infallible");

    Instruction {
        program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        accounts: vec![AccountMeta::new(payer, true), AccountMeta::new(tree, false)],
        data: instruction_data,
    }
}
```

- Use canonical program ids from `program-libs/interface/src/lib.rs`, do not pass as parameter
- Use fixed-size arrays for instruction data, not Vec, when the instruction data is fixed
- Add `pub mod <name>;` + `pub use <name>::<item>;` to `program-libs/interface/src/instruction/builders/mod.rs`
- Builders are imported in tests as `zolana_interface::instruction::<builder>`

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
3. Every account that is read or written to must be accessed with a load prefixed function that is defined in a loader.rs file
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

### Crate hierarchy

1. the program must only depend on the interface crate and possibly other low level crates that pull in as few dependencies as possible it must not depend on its own sdks
2. sdks must not depend on test-utils not in deps or dev-deps

### Proof generation for tests

1. Loading proving keys for big circuits takes a lot of time
2. tests should start a prover server if not started yet
3. The prover server should be lazy it should not load any proving keys on startup it should load them when a proof for that key is requested and then keep it loaded so that the key doesnt need to be loaded again

## Git Hygiene

The worktree may contain user changes. Do not revert unrelated edits. Keep PRs
small when possible: protocol/program changes, tooling cleanup, and prover
renames should be split unless the task explicitly asks for a combined change.
