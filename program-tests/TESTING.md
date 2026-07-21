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

| Binary | Functional | Failing | Edge cases | Random |
| --- | --- | --- | --- | --- |
| `admin` | `tests/admin/functional.rs` | `tests/admin/failing.rs` | `tests/admin/edge_cases.rs` | — |
| `deposit` | `tests/deposit/functional.rs` | `tests/deposit/failing.rs` | `tests/deposit/edge_cases.rs` | `tests/deposit/random.rs` |
| `dispatch` | `tests/dispatch/functional.rs` | `tests/dispatch/failing.rs` | — | — |
| `spl` | `tests/spl/functional.rs` | `tests/spl/failing.rs` | — | — |

Mollusk helpers and fixtures shared by the `admin` and `deposit` binaries live
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
