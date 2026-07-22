# Program test strategy

Program behavior is covered in layers. A failure should identify the smallest
boundary that is broken, while the local-validator suites remain the final
end-to-end check.

| Layer | What it proves | Primary command |
| --- | --- | --- |
| Rust unit/property | Serialization, builders, wallet rules, and pure invariants | `just test-sdk-libs` |
| LiteSVM | Real SBF dispatch, state transitions, signatures, balances, and exact errors | `just test-program-fast` |
| Mollusk | Exact malformed-input failures, account-contract mutations, deterministic execution, and rollback for shielded-pool and swap SBF | `just test-program-mollusk` |
| Groth16 integration | Every supported transfer/merge shape and ownership rail proves and verifies | `just test-program-proofs` |
| Validator + Photon | RPC submission, CPI, indexing, wallet sync, lifecycle rollback, and deterministic workloads | `just test-spp-validator`, `just test-zone-validator` |
| Cross-program swap | Swap, shielded pool, registry, smart-account, prover, and indexer compose correctly | `just test-swap-validator` |

## Coverage map

| Behavior | LiteSVM | Mollusk | Proof integration | Validator |
| --- | :---: | :---: | :---: | :---: |
| Protocol/tree/SPL administration | ✓ | account mutations | — | ✓ |
| SOL and SPL deposits | ✓ | exact errors + rollback | — | ✓ |
| P256 and EdDSA transfers | ✓ | malformed dispatch | every supported shape | ✓ |
| Mixed public SOL/SPL amounts | ✓ | malformed dispatch | fixed-shape matrices | ✓ |
| Withdrawals | ✓ | malformed dispatch | SOL/SPL matrices | ✓ |
| Merge and merge-zone | ✓ | malformed dispatch | padding and both rails | ✓ |
| Zone authority and policy gates | ✓ | account mutations | shapes, owners, boundary | ✓ |
| Rejected-transaction atomicity | full account snapshots | full account snapshots | — | full account snapshots |
| Wallet/indexer consistency | — | — | fixture indexer | ✓ |

Shielded-pool LiteSVM and Mollusk coverage is organized by instruction family:

| Instruction family | Functional binary | Rejection binary | Model/property binary |
| --- | --- | --- | --- |
| protocol config | `protocol_config_contract` | `admin_rejection` | `evolution_contract` |
| tree/pause | `tree_contract` | `admin_rejection` | `deposit_model` |
| deposit | `deposit_functional` | `deposit_rejection` | `deposit_model`, `deposit_mutation` |
| dispatch | `dispatch_contract` | `dispatch_contract` | — |
| SPL interface | `spl_interface_contract` | `spl_rejection` | — |
| zone config | `zone_config_contract` | `admin_rejection` | `authorization_contract` |
| transact | `transact_contract` | `settlement_guard_contract` | `protocol_model` |
| withdrawal | `withdrawal_contract` | `settlement_guard_contract` | `protocol_model` |
| P256 ownership | `p256_contract` | `p256_contract` | `authorization_contract` |
| expiry and replay | `withdrawal_contract` | `withdrawal_contract` | `temporal_contract` |
| nullifier batches | `localnet_photon_e2e` | `localnet_photon_e2e` | `nullifier_batch_contract` |
| merge | validator/proof matrices | validator rejection matrix | `merge_contract` |
| authority/registry evolution | `admin_functional`, `withdrawal_contract` | `admin_rejection` | `evolution_contract` |
| compute budgets | `cu_budget_contract`, `bench_cu` | — | `proof_cu`, `localnet_photon_e2e` |

Run a single intent-level binary with `just test-shielded-pool-case <binary>`.
The aggregate `just test-program-fast` continues to run every ungated binary.

`deposit_model` executes generated deposit/pause lifecycles against an
independent expected-state ledger. After every action it compares depositor and
vault balances, tree/indexer roots, leaf order, and every indexed proofless
payload. `deposit_mutation` separately covers malformed byte/account mutations,
determinism, and rollback; mutation testing is not used as a substitute for the
behavioral model.

`protocol_model` is the backend-neutral protocol state machine. Its 512-case
differential property compares UTXO selection, change, custody, and public
balances with a separately implemented balance ledger. A second 256-case model
runs 24–179 action mixed data/control-plane histories (deposits, transfers,
withdrawals, pause, authority and registry rotation, zone/merge policy, and
clock changes) and asserts exact rollback and conservation after every action.

The focused `temporal_contract`, `authorization_contract`,
`nullifier_batch_contract`, and `evolution_contract` binaries pin boundary and
lifecycle behavior without a prover. The proof-backed `withdrawal_contract`
also submits a real proof one second after its bound expiry, checks automatic
account rollback, then retries the identical instruction exactly at the expiry
boundary. Its UTXO was created before a protocol-authority rotation.

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
`assert_rolled_back_except(&[fee_payer])` for rejection atomicity. This removes
manual snapshot drift and makes failures replayable from the journaled action
or transaction history.

`cu_budget_contract` pins all proofless administration variants, tree
creation/pause, SPL registration, and SOL/SPL deposits to transaction-level CU
ceilings. `bench_cu` enforces a ceiling and retains internal profiler breakdowns
for every supported EdDSA transact shape (`1x1`, `1x2`, `2x2`, `2x3`, `3x3`,
`4x3`, `4x4`, `5x3`, `5x4`, and `1x8`) plus SOL/SPL withdrawals. There is no
separate split instruction: `1x8` is the widest split-shaped transact.

P256 commitment verification and policy-zone CPI behavior require the real
validator; Mollusk's pairing stubs are not treated as authoritative CU data. The
focused `proof_cu` binaries therefore pin P256 transact, zone EdDSA/P256
transact, P256 and zone withdrawals, zone-authority transact, maximal `8x1`
merge, and maximal `8x1` merge-zone using confirmed transaction metadata. This is an orthogonal matrix:
the EdDSA profiler covers shape-dependent input/output work, while validator
tests cover each extra proof rail and CPI boundary. The Photon forester lifecycle
also pins every submitted batch nullifier-tree update. Run these focused checks
with `just test-spp-validator-proof-cu`, `just test-zone-validator-proof-cu`, and
`just test-nullifier-batch-proof-cu`.

Mollusk helpers and fixtures shared by the admin and deposit binaries live
in `tests/common/mollusk.rs`.

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

`just test-program-mollusk` runs the complete shielded-pool `admin` and
`deposit` binaries plus the swap rejection binary. That includes the
deterministic `proptest` mutations against the real SBF program, exact failures,
edge cases, success fixtures, and rollback checks. This is property-based
mutation testing, not a coverage-guided fuzzing campaign.

The shielded-pool fixtures cover deposits, protocol-config creation, and tree
pause administration. Swap rejection coverage is organized by wrapper under
`sdk-tests/zk-program-swap/program/tests/failing/`; it covers every wrapper's
dispatch and wire boundary, marker shape, SPP program identity, canonical order
authority, signer/writable privileges, account ordering, exact errors, and
rollback.

To export native Mollusk JSON fixtures from the malformed-deposit rejection
tests in `tests/deposit/failing.rs`:

```sh
just eject-mollusk-fixtures
```

Generated fixtures go under the workspace-root `target/` by default and are
not source artifacts. The recipe resolves a custom output to an absolute path
before Cargo starts the package test process.
Run `just check-test-hygiene` before committing test-structure changes.
