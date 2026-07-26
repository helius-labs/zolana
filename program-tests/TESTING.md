# Program test strategy

Program behavior is covered in layers. A failure should identify the smallest
boundary that is broken, while the local-validator suites remain the final
end-to-end check.

| Layer | What it proves | Primary command |
| --- | --- | --- |
| Rust unit/property | Serialization, builders, wallet rules, and pure invariants | `just test-sdk-libs` |
| LiteSVM | Real SBF dispatch, state transitions, signatures, balances, and exact errors | `just test-program-fast` |
| Mollusk | Exact malformed-input failures, account-contract mutations, and deterministic execution for shielded-pool and swap SBF | `just test-program-mollusk` |
| Groth16 integration | Every supported transfer/merge shape and ownership rail proves and verifies | `just test-program-proofs` |
| Validator + Photon | RPC submission, CPI, indexing, wallet sync, lifecycle rollback, and seed-replayable randomized workloads | `just test-spp-validator`, `just test-zone-validator` |
| Cross-program swap | Swap, shielded pool, registry, smart-account, prover, and indexer compose correctly | `just test-swap-validator` |

## Coverage map

| Behavior | LiteSVM | Mollusk | Proof integration | Validator |
| --- | :---: | :---: | :---: | :---: |
| Protocol/tree/SPL administration | ✓ | account mutations | — | ✓ |
| SOL and SPL deposits | ✓ | exact errors | — | ✓ |
| P256 and EdDSA transfers | ✓ | malformed dispatch | every supported shape | ✓ |
| Mixed public SOL/SPL amounts | ✓ | malformed dispatch | fixed-shape matrices | ✓ |
| Withdrawals | ✓ | malformed dispatch | SOL/SPL matrices | ✓ |
| Merge and merge-zone | ✓ | malformed dispatch | padding and both rails | ✓ |
| Zone authority and policy gates | ✓ | account mutations | shapes, owners, boundary | ✓ |
| Rejected-transaction atomicity | full account snapshots | not asserted; failures return input copies | — | full account snapshots |
| Wallet/indexer consistency | — | — | fixture indexer | ✓ |

Shielded-pool LiteSVM and Mollusk coverage is organized by instruction family.
The "Model/property binary" column names reference-model and property suites
that run against the in-process transition oracle, not the SBF program; the
functional/rejection columns (plus the proof and validator tiers) are the
behavioral program coverage. `merge_contract`, `nullifier_batch`, and
`protocol_config_contract` additionally run real-SBF negatives alongside their
model cases.

| Instruction family | Functional binary | Rejection binary | Model/property binary |
| --- | --- | --- | --- |
| protocol config | `protocol_config_contract` | `admin_rejection`, `admin_edge_cases` | `cross_cutting_evolution` |
| tree/pause | `tree_contract` | `admin_rejection` | `deposit_model` |
| deposit | `deposit_functional` | `deposit_rejection`, `deposit_edge_cases` | `deposit_model`, `deposit_mutation` |
| dispatch | `dispatch_functional` | `dispatch_rejection` | — |
| SPL interface | `spl_interface_contract` | `spl_interface_rejection` | — |
| zone config | `zone_config_contract` | `admin_rejection` | `cross_cutting_authorization` |
| transact | `transact_functional` | `transact_settlement` | `cross_cutting_protocol_model` |
| withdrawal | `transact_withdrawal` | `transact_settlement` | `cross_cutting_protocol_model` |
| P256 ownership | `transact_p256` | `transact_p256` | `cross_cutting_authorization` |
| expiry and replay | `transact_withdrawal`, proof/validator transact suites | proof/validator nullifier and merge-tag replay | `cross_cutting_temporal` |
| nullifier batches | `localnet_photon` | `localnet_photon` | `nullifier_batch` |
| merge | validator/proof matrices | validator rejection matrix | `merge_contract` |
| authority/registry evolution | `admin_functional`, `transact_withdrawal` | `admin_rejection` | `cross_cutting_evolution` |
| compute budgets | `cross_cutting_cu_budget`, `bench_cu` | — | `proof_cu`, `localnet_photon` |

Run a single intent-level binary with `just test-shielded-pool-case <binary>`.
The aggregate `just test-program-fast` continues to run every ungated binary.

`deposit_model` executes generated deposit/pause lifecycles against an
independent expected-state ledger. After every action it compares depositor and
vault balances, tree/indexer roots, leaf order, and every indexed proofless
payload. `deposit_mutation` separately covers malformed byte/account mutations,
determinism; mutation testing is not used as a substitute for the
behavioral model.

`cross_cutting_protocol_model` is the backend-neutral protocol state machine. Its 512-case
differential property compares UTXO selection, change, custody, and public
balances with a separately implemented balance ledger. A second 256-case model
runs 24–179 action mixed data/control-plane histories (deposits, transfers,
withdrawals, pause, authority and registry rotation, zone/merge policy, and
clock changes) and checks conservation plus a separately implemented
control-plane shadow (authorization outcomes and authority/pause/registry/
zone/merge/clock state) after every action, so the model's own clone-restore
rollback is not the only oracle.

The focused `cross_cutting_temporal`, `cross_cutting_authorization`,
`nullifier_batch`, and `cross_cutting_evolution` binaries pin boundary and
lifecycle behavior without a prover. The proof-backed `transact_withdrawal`
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
every property suite (`cross_cutting_protocol_model`, `deposit_model`, `deposit/mutation`, the
interface `parser_props`/`state_props`, `wallet_prop`); only `wallet_prop` has
persisted a seed so far because the others have not yet failed.

## Shared backend, oracle, and transaction journal

`zolana_test_utils::backend::LiteSvmPoolBackend` is the common proofless
workflow backend used by shielded-pool tests. The backend owns protocol/tree
setup, signer funding, and exposes the transaction journal. New workflow
backends use the `ShieldedPoolBackend` vocabulary in
`zolana_test_utils::state_model` so decoded post-state can be compared with the
same transition oracle.

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

P256 commitment verification and policy-zone CPI behavior require the real
validator; Mollusk's pairing stubs are not treated as authoritative CU data. The
focused `proof_cu` binaries therefore pin P256 transact, zone EdDSA/P256
transact, P256 and zone withdrawals, zone-authority transact, maximal `8x1`
merge, and maximal `8x1` merge-zone using confirmed transaction metadata. This is an orthogonal matrix:
the EdDSA profiler covers shape-dependent input/output work, while validator
tests cover each extra proof rail and CPI boundary. The Photon forester lifecycle
also pins every submitted batch nullifier-tree update when the in-test
forester drives the batches; the `FORESTER_BIN` end-to-end mode asserts only
the final root index. Run these focused checks
with `just test-spp-validator-proof-cu`, `just test-zone-validator-proof-cu`, and
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

Tests never silently skip because an artifact is absent.

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
