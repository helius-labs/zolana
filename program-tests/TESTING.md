# Program test strategy

Program behavior is covered in layers. A failure should identify the smallest
boundary that is broken, while the local-validator suites remain the final
end-to-end check.

| Layer | What it proves | Needs running | Primary command |
| --- | --- | --- | --- |
| Rust unit/property | Serialization, builders, wallet rules, and pure invariants | nothing | `just test-sdk-libs` |
| LiteSVM | Real SBF dispatch, state transitions, signatures, balances, and exact errors | the SBF build | `just test-program-fast` |
| Mollusk | Exact malformed-input failures, account-contract mutations, and deterministic execution for shielded-pool and swap SBF | the SBF build | `just test-program-mollusk` |
| Groth16 integration | Every supported transfer/merge shape and ownership rail proves and verifies | prover server, proving keys | `just test-program-proofs` |
| Validator + Photon | RPC submission, CPI, indexing, wallet sync, lifecycle rollback, and seed-replayable randomized workloads | validator, Photon, prover, proving keys | `just test-spp-validator`, `just test-ring-validator` |
| Cross-program swap | Swap, shielded pool, registry, smart-account, prover, and indexer compose correctly | validator, Photon, prover, proving keys | `just test-swap-validator` |

The first three layers are hermetic and run together as `just test-hermetic`.
CI runs these same suites on every push. `just test-all` adds the Groth16
layer, and the validator layers stay in their own recipes. Each non-hermetic
tier is behind a Cargo feature, `proofs` or `localnet`, so a plain `cargo test
-p <crate>` selects only the hermetic binaries.

## Coverage map

| Behavior | LiteSVM | Mollusk | Proof integration | Validator |
| --- | :---: | :---: | :---: | :---: |
| Protocol/tree/SPL administration | ✓ | account mutations | — | ✓ |
| SOL and SPL deposits | ✓ | exact errors | — | ✓ |
| P256 and EdDSA transfers | ✓ | malformed dispatch | every supported shape | ✓ |
| Mixed public SOL/SPL amounts | ✓ | malformed dispatch | fixed-shape matrices | ✓ |
| Withdrawals | ✓ | malformed dispatch | SOL/SPL matrices | ✓ |
| Merge and merge-ring | ✓ | malformed dispatch | padding and both rails | ✓ |
| Ring authority and policy gates | ✓ | account mutations | shapes, owners, boundary | ✓ |
| Rejected-transaction atomicity | full account snapshots | not asserted; failures return input copies | — | full account snapshots |
| Wallet/indexer consistency | — | — | fixture indexer | ✓ |

Shielded-pool LiteSVM and Mollusk coverage is organized by instruction family.
The "Model/property binary" column names behavioral-model and property suites
that drive the real program (in LiteSVM or Mollusk) against an independent
expected-state ledger; the functional/rejection columns (plus the proof and
validator tiers) are the rest of the behavioral program coverage.

| Instruction family | Functional binary | Rejection binary | Model/property binary |
| --- | --- | --- | --- |
| protocol config | `protocol_config_contract` | `admin_rejection`, `admin_edge_cases` | — |
| tree/pause | `tree_contract` | `admin_rejection` | `deposit_model` |
| deposit | `deposit_functional` | `deposit_rejection`, `deposit_edge_cases` | `deposit_model`, `deposit_mutation` |
| dispatch | `dispatch_functional` | `dispatch_rejection` | — |
| SPL interface | `spl_interface_contract` | `spl_interface_rejection` | — |
| ring config | `ring_config_contract` | `admin_rejection` | — |
| transact | `transact_functional` | `transact_settlement` | — |
| withdrawal | `transact_withdrawal` | `transact_settlement` | — |
| expiry and replay | `transact_withdrawal`, proof/validator transact suites | proof/validator nullifier and merge-tag replay | — |
| nullifier batches | `localnet_photon` | `localnet_photon`, `nullifier_batch` | — |
| merge | validator/proof matrices | validator rejection matrix, `merge_contract` | — |
| authority/registry evolution | `admin_functional`, `transact_withdrawal` | `admin_rejection` | — |
| compute budgets | `cross_cutting_cu_budget`, `bench_cu` | — | `proof_cu`, `localnet_photon` |

Run a single intent-level binary with `just test-shielded-pool-case <binary>`.
The aggregate `just test-program-fast` continues to run every ungated binary.

`deposit_model` executes generated deposit/pause lifecycles against an
independent expected-state ledger. After every action it compares depositor and
vault balances, tree/indexer roots, leaf order, and every indexed proofless
payload. `deposit_mutation` separately pins each malformed-input class
(truncations, removed/swapped/readonly accounts, unsigned or unfunded
depositors, wrong tree owner/data) to its exact typed rejection, keeping
determinism-only proptests for the byte flips that remain self-consistent
deposits; mutation testing is not used as a substitute for the
behavioral model.

The proof-backed `transact_withdrawal`
also submits a real proof one second after its bound expiry, checks automatic
account rollback, then retries the identical instruction exactly at the expiry
boundary. Its UTXO was created before a protocol-authority rotation.

### Proptest regression corpora (commit them)

When a `proptest!` case fails, proptest writes the failing seed to a sibling
`<suite>.proptest-regressions` file (e.g.
`sdk-libs/transaction/tests/wallet_prop.proptest-regressions`) and replays it
before any novel case on the next run. **Commit that file**: it turns a
one-time discovery into a permanent regression guard for everyone. The
`proptest-regressions` files are intentionally not gitignored. This applies to
every property suite (`deposit_model`, `deposit/mutation`, the
interface `parser_props`/`state_props`, `wallet_prop`); `wallet_prop` and
`deposit/mutation` have persisted seeds so far because the others have not yet
failed.

## Shared backend, oracle, and transaction journal

`zolana_test_utils::backend::LiteSvmPoolBackend` is the common proofless
workflow backend used by shielded-pool tests. The backend owns protocol/tree
setup, signer funding, and exposes the transaction journal.

Every `ZolanaProgramTest` submission, successful or rejected, captures:

- every message account before and after execution;
- instruction program, account layout, discriminator, and data length;
- logs, compute units, signature, and typed outcome.

Use `last_transaction_trace().diagnostic()` for failure context and
`assert_rolled_back_except(&[fee_payer])` to sanity-check the journaled
snapshots of a rejected transaction (the runtime itself guarantees the
rollback; the assert catches journal drift and unexpected fee-payer-adjacent
writes). This removes manual snapshot drift and makes failures replayable from
the journaled action or transaction history.

LiteSVM pool-error assertions use
`Rejection::pool(ShieldedPoolError::X).assert_litesvm(err)` (from
`zolana_program_test::Rejection`), with `.at(index)` when the failing
instruction index matters.

`cross_cutting_cu_budget` pins all proofless administration variants, tree
creation/pause, SPL registration, and SOL/SPL deposits to per-family CU
ceilings chosen strictly below the enforced transaction budget, so a
consumption regression fails the ceiling assert rather than aborting at the
budget. `bench_cu` asserts transact ceilings and retains internal profiler
breakdowns for every supported EdDSA transact shape (`1x1`, `1x2`, `2x2`,
`2x3`, `3x3`, `4x3`, `4x4`, `5x3`, `5x4`, and `1x8`) plus SOL/SPL withdrawals,
but only under the manual `just bench-shielded-pool` run (it needs the
profiling SBF build); CI does not execute those transact ceilings. There is no
separate split instruction: `1x8` is the widest split-shaped transact.

P256 commitment verification and policy-ring CPI behavior require the real
validator; Mollusk's pairing stubs are not treated as authoritative CU data. The
focused `proof_cu` binaries therefore pin P256 transact, ring EdDSA/P256
transact, P256 and ring withdrawals, ring-authority transact, maximal `8x1`
merge, and maximal `8x1` merge-ring using confirmed transaction metadata. This is an orthogonal matrix:
the EdDSA profiler covers shape-dependent input/output work, while validator
tests cover each extra proof rail and CPI boundary. The Photon forester lifecycle
also pins every submitted batch nullifier-tree update when the in-test
forester drives the batches; the `FORESTER_BIN` end-to-end mode asserts only
the final root index. Run these focused checks
with `just test-spp-validator-proof-cu`, `just test-ring-validator-proof-cu`, and
`just test-nullifier-batch-proof-cu`.

Shared setup is owned by the `shielded_pool_tests` support library under
`src/support/`: `runtime` (SBF boot and account sizing), `fixtures` (initialized
LiteSVM environments and instruction/account builders), `mollusk` (Mollusk
snapshot fixtures shared by the admin and deposit binaries), and `forester` (the
localnet nullifier-tree driver, gated behind the `localnet` feature). Test
binaries import it as `shielded_pool_tests::support::*`; there are no `#[path]`
wrapper entrypoints.

User-registry LiteSVM coverage has its own artifact-aware entry point:
`just test-user-registry-litesvm`. It is also included by `just test-all` and by
the dedicated CI `test-user-registry-litesvm` job.

## Artifact contract

Tests never silently skip because an artifact is absent. A test that needs an
artifact panics with the command that produces it.

- `just build-programs` must produce the SBF files in `target/deploy`.
- `just build-cli` must produce `target/debug/zolana`.
- `just build-prover-server` must produce `target/prover-server`.
- Validator harnesses validate every required binary before startup and use
  process-specific ledger/account directories.
- Prover-backed tests pass an explicit workspace key-cache path. The prover may
  create that directory and lazily download a missing key, but an invalid parent
  path fails before process startup.
- Use `ZOLANA_PORT_OFFSET` in `.env` when multiple worktrees run local services.

## Mollusk mutation tests and fuzz fixtures

`just test-program-mollusk` runs the shielded-pool `admin_functional`,
`admin_rejection`, `deposit_functional`, `deposit_rejection`, and
`deposit_mutation` binaries plus the swap rejection binary (`deposit_model`
is LiteSVM-only and runs in the fast tier instead). That includes the
deterministic `proptest` mutations against the real SBF program, exact failures,
edge cases, success fixtures, and deterministic rejection checks. This is property-based
mutation testing, not a coverage-guided fuzzing campaign.

The shielded-pool fixtures cover deposits, protocol-config creation, and tree
pause administration. Swap rejection coverage is organized by wrapper under
`sdk-tests/zk-program-swap/program/tests/failing/`; it covers every wrapper's
dispatch and wire boundary, marker shape, SPP program identity, canonical order
authority, signer/writable privileges, account ordering, exact errors, and
deterministic re-execution. Mollusk failure results are not used to claim
rollback because the backend reports the supplied input accounts on failure.

To export native Mollusk JSON fixtures from the malformed-deposit rejection
tests in `tests/deposit/rejection.rs` (the `deposit_rejection` binary):

```sh
just eject-mollusk-fixtures
```

Only the Mollusk-backed `mollusk_deposit_rejects_*` cases eject fixtures; the
LiteSVM-backed rejection tests in the same binary never execute under Mollusk
and therefore produce none. Generated fixtures go under the workspace-root
`target/` by default and are not source artifacts. The recipe resolves a
custom output to an absolute path before Cargo starts the package test
process.
Run `just check-test-hygiene` before committing test-structure changes.

## Test tooling

Beyond `cargo test`, two tools sharpen the suite. Install locally with
`cargo install cargo-nextest cargo-llvm-cov`; CI installs nextest in
`setup-rust` and llvm-cov via `taiki-e/install-action`.

- **cargo-nextest** is the runner for every `just test-*` recipe (config in
  `.config/nextest.toml`). It runs each test in its own process with a per-test
  hang timeout — important because many tests spawn a prover/validator/photon —
  and the `ci` profile adds retries for localnet flakiness. Two consequences of
  process-per-test: (1) nextest does not run doctests, so recipes with runnable
  doctests keep a `cargo test --doc` line; (2) `#[serial]` (serial_test) is
  process-local and thus a no-op under nextest, so the validator/localnet tests
  that bind fixed ports are serialized by the `serial-validator` test-group in
  `nextest.toml` instead. The manual `bench-*` profiling recipes stay on plain
  `cargo test -- --ignored` (nextest's value does not apply there).
- **cargo-llvm-cov** (`just coverage`; `just coverage --html`) reports
  line/region coverage over the host-instrumentable kernels + SDK. It cannot
  measure code executed inside the SVM (the program's on-chain paths run as a
  separate SBF binary), so it is a diagnostic for which pure kernels lack tests,
  not a whole-program metric — the on-chain paths are covered behaviorally by
  the SVM negative suites.
