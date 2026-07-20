# Zolana Contributor Notes

## Source Of Truth

`docs/spec.md` is the protocol source of truth. Do not edit it as part of
implementation cleanup unless that is the explicit task. If code, tests, and the
spec disagree, treat the code or tests as suspect first.

## Spec Maintenance

Spec refreshes run through the `spec-review` skill
(`.claude/skills/spec-review/SKILL.md`): it compares `docs/spec.md` with the
code, fixes stale spec text, security-audits the design, and appends findings
to `docs/spec-review/findings.md` (gitignored local review state). `just
spec-gate` (CI: `spec-review.yml`) fails while any finding is `status: open`
and passes when no ledger exists; `yolo-fix-spec` marks the findings it
closes `auto-resolved` (passes CI, distinct from operator `resolved`), and a
human operator flips the rest to `acknowledged`/`resolved`. `just spec-lint` is
the deterministic spec check (dead anchors, broken links, banned vocabulary) run
by the gate job, the hook, and the skill's self-review. Headless audit runs:
`just spec-review` / `just spec-review-diff` (these never edit the spec).
`just yolo-fix-spec` is the operator-only autofix: it rewrites `docs/spec.md` to
match the code for recorded drift and to production grade, then auto-resolves
those findings — review `git diff docs/spec.md` before committing. Every fix
edit carries an adjacent `<!-- ZSR-NNNN: why -->` markdown comment, so the diff
justifies itself; strip them after review at will. The optional
pre-commit gate (`spec-gate` + `spec-lint`) is enabled with `just install-hooks`.

## Repo Structure

program-libs
- libraries used in programs
- are published as crates

programs
- must not depend on sdk libs
- are not published as crates

program-tests
- integration tests for programs
- are not published as crates

sdk-libs
- libraries to interact with programs

sdk-tests
- integration test programs for sdks

prover
- go circuits
- go prover server
- rust prover client

## Workspace Shape

- `programs/shielded-pool`: the SPP Solana program.
- `program-libs/interface`: shared instruction data, tags, constants, and layout
  helpers.
- `program-tests`: internal test crates and test-only SBF programs.
- `sdk-libs`: externally useful Rust SDK crates.
- `cli`: local developer/operator tooling.
- `forester`: compilable forester skeleton for future nullifier-tree
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
just test-programs
just test-cli
just clippy
```

Program tests that load real SBF binaries need the local builds:

```bash
just build-programs
```

### Per-clone port isolation (`ZOLANA_PORT_OFFSET`)

Localnet/prover-backed tests bind fixed ports (RPC 8899, photon 8784, prover
3001), so two clones running them at once contend. To isolate a clone, set a
single offset in a local `.env` (gitignored, auto-loaded by `just` via `set
dotenv-load`); the justfile shifts every service port by it and derives the
matching URLs:

```bash
cp .env.example .env        # then set e.g. ZOLANA_PORT_OFFSET=100
```

Offset 100 -> RPC 8999, photon 8884, prover 3101. Use 0 / 100 / 200 / ... per
clone (stay below ~900). The justfile exports `ZOLANA_PROVER_URL`, and the
tests read `ZOLANA_LOCALNET_URL` / `ZOLANA_INDEXER_URL` / `ZOLANA_PROVER_URL`,
so the offset flows into every `just test-*` recipe. Individual
`ZOLANA_LOCALNET_RPC_PORT` / `ZOLANA_LOCALNET_PHOTON_PORT` /
`ZOLANA_LOCALNET_PROVER_PORT` (and the URL vars) still override the derived
value when set explicitly.

`ZOLANA_PROVER_URL` is the single source of truth for the prover: the client
connects there and `spawn_prover()` starts the spawned server on that URL's
port. Running `cargo test` directly (not via `just`) does not auto-load `.env`
-- export the vars yourself (`set -a; source .env; set +a`) or use `direnv`.

## Code Style

- Keep protocol math in one canonical implementation and reuse it from tests.
- Keep public SDK surface deliberate; test-only helpers belong under
  `program-tests` unless they are useful to external developers.
- Avoid compatibility shims for removed Light/legacy surfaces.
- Prefer small, explicit helpers over broad abstractions.
- Comments should explain invariants, security constraints, or non-obvious
  layout decisions. Remove comments that only narrate the code.
- Never add `#[allow(clippy::too_many_arguments)]`. Restructure with the
  method-patterns skill instead: an operation struct holding all inputs plus a
  consuming method that takes only the signer/context (e.g.
  `EscrowSettle { .. }.sign(keypair, assets)`).
- Do not leak prover/circuit-internal terminology ("field element(s)",
  "witness") into public API names (types, methods, fields, modules of
  sdk-libs and sdk crates). SDK users think in proofs and their inputs: name
  such surfaces in that vocabulary (`ProofInputUtxo`, `proof_inputs`,
  `to_proof_inputs()`). Internal prover code (prover crates, Go circuits,
  private helpers) may keep the ZK terms.

## Testing

- Do not add tests that only exercise derived serialization, e.g. a borsh or
  wincode `serialize` -> `deserialize` round-trip asserting equality. They test
  the derive macro, not our code. Test behavior we actually implement
  (validation, field mapping, encode/decode logic, state transitions) instead.

## Testing

- Do not add tests that only exercise derived serialization, e.g. a borsh or
  wincode `serialize` -> `deserialize` round-trip asserting equality. They test
  the derive macro, not our code. Test behavior we actually implement
  (validation, field mapping, encode/decode logic, state transitions) instead.

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

All program errors must be defined in the interface crate
(`program-libs/interface/src/error.rs`), including the `From<...> for
ProgramError` conversion. The program crate does not define its own error enum;
it imports `zolana_interface::error::ShieldedPoolError`, and clients import the
same definition.

```rust
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum ShieldedPoolError {
    #[error("description")]
    Variant = 7000,
}
```

- The `ProgramError` conversion target is `solana_program_error::ProgramError`,
  which Pinocchio re-exports as `pinocchio::error::ProgramError` (same type), so
  the interface crate depends on `solana-program-error`, not `pinocchio`:

  ```rust
  impl From<ShieldedPoolError> for ProgramError {
      fn from(e: ShieldedPoolError) -> Self {
          ProgramError::Custom(e as u32)
      }
  }
  ```

- Meaningful errors: every fallible path must return a specific, named variant
  that describes what failed. Do not reuse an unrelated variant as a catch-all
  and do not return a bare `ProgramError::Custom`/generic error at call sites
  when a precise variant exists or could be added.

- Error codes live in the `7000` space. Pin every code in the
  `error_codes_are_stable` test. Once a code is observable by tests or clients,
  do not renumber it casually.

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

1. use [instruction-decoder](https://github.com/helius-labs/privacy-program-libs/tree/main/crates/instruction-decoder)
2. default light-zero-copy
3. if not hot path can use borsh

### wincode length prefixes (zolana-transaction)

When choosing the length encoding for a wincode `containers::Vec<T, FixIntLen<..>>`:
- `Vec<u8>` (byte vectors: ciphertexts, program/zone data, can exceed 255 bytes) use `FixIntLen<u16>`.
- every other vector (element counts: records, recipient slots, recipient viewing keys; always small) use `FixIntLen<u8>`.

### Accounts

1. instructions that transfer lamports take a fee payer account; instructions that do not must not take one
2. no need to verify pda derivation for initialized accounts: checking discriminator and program ownership is enough if access control does not rely on the derivation itself. If access control relies on the derivation, store the bump in the account data or send it in instruction data; account data is cleaner if the account has data
3. Every account that is read or written to must be accessed with a load prefixed function that is defined in a loader.rs file
4. PDA creation must use canonical bumps derived via `find_program_address` (verify_pda), never accept bumps from instruction data for account creation
5. init pattern:
    - must use a param struct with an init method `pub fn init(self, account: &AccountView) -> ProgramResult {`
    - must check that account is not already initialized
    - no program id check necessary; the SVM does not allow writes to an account owned by another program
    - all account struct fields must be initialized
    - account size must match the account struct size exactly
6. Recovery and owner encryption keys
    - the owner needs to sign to add or remove encryption keys other than auditor keys
7. all signer checks must be in the processor not nested inside of other functions
8. closing accounts
    - every account close instruction must have a dedicated rent_recipient

### Crate hierarchy

1. the program must only depend on the interface crate and possibly other low level crates that pull in as few dependencies as possible; it must not depend on its own sdks
2. sdks must not depend on test-utils, neither in deps nor dev-deps

### Proof generation for tests

1. Loading proving keys for big circuits takes a lot of time
2. tests should start a prover server if not started yet
3. The prover server should be lazy: load no proving keys on startup, load a key when a proof for it is first requested, then keep it loaded

## SPP Transaction Proving Keys & Verifying Keys

The `transfer` (eddsa, Solana-only rail) and `transfer_p256` (P256 ownership
rail) circuits live in `prover/server/circuits/spp_transaction/`. Their proving
systems are per-shape (`<nInputs>x<nOutputs>`); the supported shape set is
duplicated in four places that MUST stay in sync:
`sdk-libs/client/src/shape.rs` (the client may use a subset), Go
`prover-test/spp/protocol/shape.go` (`SupportedShapes`), Go
`prover/common/lazy_key_manager.go` (`transferSupportedShapes`), and the
shielded-pool verifier when it exists (`transact/proof.rs`).

### Generate proving keys (`.key`)

```bash
# All supported shapes, both rails -> prover/server/proving-keys/<rail>_<in>_<out>.key
prover/server/scripts/generate_keys_transfer.sh

# One shape directly (--circuit flag = transfer (eddsa) | transfer-p256).
# Key files mirror the vk modules: transfer_<shape>.key / transfer_p256_<shape>.key.
cd prover/server && go build -o light-prover .
./light-prover setup-transfer --circuit transfer-p256 --n-inputs 2 --n-outputs 3 \
    --output proving-keys/transfer_p256_2_3.key
```

`setup-transfer` runs `groth16.Setup` and writes the full `TransferProofSystem`
(pk+vk+ccs). Keys are gitignored. The server lazy-loads
`proving-keys/<rail>_<in>_<out>.key` on first proof request for that shape.

### Distribute proving keys via GitHub release

All gitignored proving keys (merkle, batch, transfer, and merge) are published
as assets on the single private-repo GitHub release `transfer-keys-v12` on
`helius-labs/zolana`. The downloader fetches release metadata and assets through
the GitHub REST API with a bearer token from `GITHUB_TOKEN` or `GH_TOKEN`. The
tag is pinned as `ProvingKeysReleaseTag` in `key_downloader.go` and can be
overridden with `PROVING_KEYS_RELEASE_TAG`; keep it aligned with
`publish_keys_release.sh` and the `proving-keys-transfer-keys-<tag>` cache key in
`.github/workflows/rust.yml` when rotating.

```bash
prover/server/scripts/publish_keys_release.sh        # publish/refresh the release
```

`EnsureProvingKeyFromRelease` verifies an existing key against the local
`CHECKSUM` first (offline, no network). Missing or mismatched keys are downloaded
from the release via the REST API, then verified against the merged release
`CHECKSUM`. CI jobs set `GH_TOKEN` and cache `prover/server/proving-keys` by tag.

### Regenerate Rust verifying keys (`program-libs/interface/src/verifying_keys/`)

```bash
prover/server/scripts/regenerate_all_vkeys.sh
```

Pipeline: `light-prover export-vk` writes the gnark `WriteRawTo` (uncompressed)
vk binary, then `cargo run -p xtask -- bsb22-vk <vk_bin> <out_dir> <filename>`
calls `groth16_solana::gnark_vk_parser::generate_bsb22_vk_file` to emit a
`pub const VERIFYINGKEY: Groth16Verifyingkey` per circuit, and `mod.rs` is
regenerated. The codegen lives in the `xtask` crate, which depends on the
`groth16-solana` fork (`../groth16-solana`, `features = ["bsb22"]`).
`zolana-interface` depends on the same fork only to compile the committed
`verifying_keys/*.rs` constants.

### BSB22 commitments (the two rails differ on purpose)

- **transfer_p256 (P256):** the emulated-P256 gadget adds one BSB22 commitment over
  private wires. Its vk has `vk_commitment_g2: Some(..)` and `vk_ic.len() ==
  public_inputs + 2`. Proofs include `proof_commitment` + `proof_commitment_pok`.
  Verify with `Groth16Verifier::new_with_commitment`.
- **transfer (eddsa, Solana-only):** standard Groth16, zero commitments. Its vk
  has `vk_commitment_g2: None` and `vk_ic.len() == public_inputs + 1`. Verify
  with `Groth16Verifier::new`.

Both verify in one binary built with the `bsb22` feature: `verify_common` runs
the standard Groth16 pairing for every proof and only adds the Pedersen PoK
pairing when a commitment is present. Dispatch on `vk.vk_commitment_g2.is_some()`
(or the rail). The Go prover marshals `proof_commitment` as `omitempty`, so it is
absent for the eddsa rail and present for the P256 rail.

NOTE: the parser/verifier support a single commitment over **private** wires
only (empty `committed_wires`). Committing a **public** input (e.g.
`committer.Commit(c.PublicInputHash)`) records that wire in
`PublicAndCommitmentCommitted` and the parser rejects it with
`Bsb22UnsupportedMultiCommitment`. The eddsa rail must therefore stay standard
Groth16 (no explicit `Commit`), not force a public-wire commitment.

## Releasing Photon

Photon lives at `services/photon` and is a member of this Cargo workspace. Build
the operational binary with `just build-photon`; localnet and CI must run that
same-revision binary rather than a downloaded release artifact. Photon consumes
the workspace `zolana-event`, `zolana-interface`, and `zolana-tree` crates, so
program layouts and indexer parsing change atomically.

Production containers are built from the repository root so Cargo can resolve
workspace path dependencies:

```bash
docker build -f services/photon/Dockerfile .
```

Photon keeps its own deployment approval even though it shares source and a
lockfile with the protocol. Release images must be immutable, identify the
Zolana repository commit, and include the root license and third-party notices.
Localnet tests never consume those production images.

From the commit on `main` to release, create and push its fork tag:

```bash
tag="photon-zolana-$(git rev-parse --short=12 HEAD)"
git tag "$tag"
git push origin "$tag"
```

A manual `photon-image.yml` dispatch must use that same commit-derived value
for its `image_tag`. The protected `photon-production` environment gates
publication. The workflow publishes the
`photon-zolana-<12-character-commit>` tag and a full `sha-<commit>` alias,
refuses to overwrite either, and does not publish `latest`. The imported crate
version in `services/photon/Cargo.toml` is upstream source provenance, not the
Zolana fork's release identifier.

Before archiving the standalone Photon repository, update external deployment
configuration that consumes its old `<run>-<sha>` or `latest` tags to use a new
immutable `photon-zolana-*` or `sha-*` tag from this repository. Keep the
base-image digests in `services/photon/Dockerfile` updated through reviewed
changes.

## Git Hygiene

The worktree may contain user changes. Do not revert unrelated edits. Keep PRs
small when possible: protocol/program changes, tooling cleanup, and prover
renames should be split unless the task explicitly asks for a combined change.

## Solana account deserialization
- never deserialize an account twice

1. use solana_address::Address NOT solana_pubkey::Pubkey which is an alias of Address
