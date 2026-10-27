# Xark migration plan for zolana program

Replace the `zk-tools` circuit dependencies used by `zolana-program` and its
supporting SDK crates with Xark. Preserve the escrow program's circuit logic and
UTXO API wherever practical. Use Xark's own input macros and prover machinery;
keep Zolana code for protocol hashes, UTXO operations, transaction construction,
and the connection to the SPP proof.

## Agreed scope

1. Breaking changes are allowed. The client API, generated bindings, build
   commands, proof artifacts, and input declarations may change.
2. Preserve the program-author API where it matters: escrow and withdraw should
   keep their business logic, UTXO operations, and transaction registration. Aim
   for import-only changes; changing input annotations and the bounded input
   declaration is acceptable when that avoids recreating obsolete machinery.
3. Prefer Xark's `#[input]` and `#[circuit]` over retaining `ProofInput` and other
   generic derives. Retain custom macros only for Zolana-specific behavior or
   the small entrypoint bridge needed to preserve existing circuit bodies.
4. Implement bounded inputs with an ArrayVec-style container and a fixed-width
   encoding. Escrow's five-input capacity is known when compiling its circuit.
5. Benchmark before and after migration, including native and browser proving.
6. Use the latest commit of Xark's `remove-nightly-compiler` development branch.
   Pin the selected revision for reproducible builds and comparisons.

The selected revision, fetched and checked out on 2026-10-27, is
`b443d83ea8ec7f2253610887e9690623ad048aef` in
`~/dev/experiments/xark`. This is Xark 0.3.0 development code with the stable
Rust/WASM frontend. Build tools from that revision; existing binaries left from
`master` may still be version 0.2.1.

## Target architecture

| Responsibility | Implementation |
| --- | --- |
| Input schemas, encoding, and generic input macros | Xark `Input` and `#[input]` |
| Circuit compilation and constraint generation | Xark stable Rust/WASM frontend |
| Witness generation, proving, and key artifacts | Xark |
| Browser proving and generic generated clients | Xark, integrated with the Zolana client |
| Protocol Poseidon, byte packing, and hash domains | Zolana gadgets written with Xark primitives |
| Owners, assets, UTXOs, state transitions, and balances | Zolana protocol library over Xark |
| Finalized SPP transactions and output encryption | Zolana SDK |
| State discriminators, state encoding, and public commitment layout | Zolana protocol code and focused macros |
| Escrow and withdraw business logic | Existing program code, with minimal source changes |

The final `zolana-program` dependency graph, including its circuit features and
supporting crates, must contain no `zolana-zk-dsl`, `zolana-zk-gadgets`,
`zolana-zk-macros`, or `zolana-zk-macros-core` dependency from `zk-tools`.
The SPP's existing Go circuits and prover are outside this migration.

## Implementation sequence

### 1 Record the existing behavior and benchmark baseline

- Record the Zolana commit, current `zk-tools` revision, compiler versions,
  machine, browser, worker count, build flags, and benchmark inputs.
- Capture escrow and withdraw behavior for SOL and an SPL asset, including
  different real-input counts within the five-slot capacity and dummy padding.
- Run the existing native scenario benchmark with `just bench-zolana-program`
  and the browser benchmark with `just bench-zk-program-wasm`. Preserve raw
  results and identify which fixtures match the timelock escrow program. Add a
  focused timelock measurement if the existing fixtures differ materially.
- Record constraints, clean and incremental circuit compilation time, native
  and browser transaction/input preparation, key loading, cold and repeated
  proof generation, verification, peak memory, and artifact sizes. Record
  verification CU if changing the on-chain verifier path.
- Separate proof generation from self-verification, or include the same work
  on both sides. Compare the same scenarios, padding, build mode, and worker
  counts. Use repeated runs and report medians with variation.

Deliverable: reproducible baseline commands, fixtures, and measurements saved
before replacing the existing implementation. Historical benchmark tables are
reference material; collect a fresh baseline on the comparison machine.

### 2 Establish the Xark build and input model

- Pin all Xark dependencies and tool invocations to the selected development
  revision. Keep the local checkout useful for development without making its
  absolute path a committed dependency.
- Build and smoke-test that revision's CLI, native execution, circuit
  compilation, setup, and proving paths.
- Use `#[input]` for ordinary input structs and implement Xark `Input` for
  Zolana-owned protocol types as needed. Generate a distinct circuit type only
  when its representation genuinely differs from the client type; use an alias
  where one type suffices to preserve existing names.
- Implement the bounded ArrayVec-style UTXO input. Its encoding always contains
  all `N` slots, with canonical dummy padding and any required occupancy checks.
  Keep the logical length private if it is represented. Preserve compact and
  explicit dummy-padding behavior at the SPP transaction boundary.
- If using the external `arrayvec` crate, implement Xark's external input trait
  through an SDK-owned wrapper to satisfy Rust's orphan rules.
- Verify empty, partial, full, excessive, and malformed input cases. Optional
  input groups must retain their existing owner and asset checks.

Deliverable: Xark input types and bounded UTXO encoding without the old
`ProofInput` allocator machinery.

### 3 Port protocol hashes exactly

- Implement the existing light-poseidon/circom-compatible Poseidon over Xark
  primitives for every arity used by the SDK. Xark's bundled Poseidon uses
  different parameters and a different multi-input construction.
- Preserve byte order, checked byte packing, state discriminators, owner and
  asset commitments, unique-address derivation, blinding domains, public
  transfers, and the zero-skipping hash chains.
- Compare native and circuit results against existing implementations and
  vectors, including leading zeroes, field boundaries, dummy entries, and every
  hash arity actually used.

Deliverable: identical protocol commitments across the old implementation,
native Xark execution, and compiled Xark circuits.

### 4 Port the UTXO API and preserve escrow circuit bodies

- Port circuit code in `sdk-libs/keypair`, `sdk-libs/transaction`, and
  `sdk-libs/program` to Xark. Changing re-exports alone is insufficient.
- Preserve the operations escrow uses: owner identity, asset selection,
  `TokenUtxos::new_mut`, `DataUtxo::new_init` and `new_mut`, state access,
  transfers, closing, and `ConfidentialTransaction::with(...).check()`.
- Keep wider intermediate balances and explicit narrowing checks. Native
  `u64` arithmetic alone does not reproduce the existing accumulation rules.
  Preserve generic bounded-integer behavior used by other SDK programs where
  Xark's native integer types do not cover it.
- Retain native transaction construction and encrypted state serialization.
  Keep extraction of concrete state bytes outside constraint execution.
- Preserve existing `Result` and `?` usage where practical. The generated
  entrypoint must reject every error path through constraints or an impossible
  execution path. A failure on the native path alone is insufficient.
- Keep `UtxoState` and `PublicInputs` generation focused on protocol-specific
  behavior. Replace the dependency on `zolana-zk-macros-core`; delegate generic
  schema generation to Xark.
- Generate a small Xark entrypoint that calls the existing circuit body.
  Generate separate build targets for escrow and withdraw so their exported
  Xark entrypoints do not collide.

Deliverable: the timelock escrow and withdraw circuit bodies compile over Xark,
with a reviewed source diff identifying any required program-facing changes.

### 5 Connect proofs to SPP and update client tooling

- Preserve exactly one application public input, `public_hash`, and constrain it
  to the existing hash of the program's public fields and transfer-aware
  transaction commitment. The verifier derives it from the actual instruction
  fields and SPP transaction.
- Preserve the shared `private_tx_hash` between the application proof and SPP
  proof, including input ordering, output ordering, dummy handling, addresses,
  public transfers, and blinding derivation.
- Adapt native execution results to `FinalizedTransaction` and the SPP proof
  inputs. Preserve the checks that constructed outputs and hashes match the
  application's committed transaction.
- Use Xark's proof and key artifacts and adapt the SDK verifier boundary.
  Prefer keeping escrow's verification call and instruction flow stable. A
  proof encoding adapter can preserve the current compressed ABI; generated
  verifier or ABI changes are allowed if they materially simplify the design.
  Resolve this using a proof verified on the actual Solana path.
- Generate new keys and verifying keys for the migrated circuits. Existing
  circuit-specific keys cannot be reused. Keep test setup distinguished from
  the production ceremony path.
- Update `zolana zk`, verifier generation, client transaction APIs, TypeScript
  bindings, and browser proving around Xark artifacts. Pin deployed circuit
  artifacts and keys, and check malformed or mismatched inputs are rejected.

Deliverable: escrow and withdraw each build a transaction, produce the
application and SPP proofs, and verify through the Solana program path.

### 6 Validate behavior and collect the after benchmarks

- Run the existing escrow functional and integration scenarios through the
  migrated implementation, including SOL and SPL lock and withdrawal flows.
- Reject wrong creators, wrong owners or assets, invalid state, zero or
  excessive amounts, overflow, malformed padding, changed public fields,
  changed public hashes, and application/SPP proofs from different transactions.
- Preserve the on-chain unlock-time and signer checks. Test state commitments
  against decrypted output data and the native transaction builder.
- Adapt the existing invariant and tampering tests to inspect compiled Xark
  constraints. Retain explicit coverage for variables whose guarantees come
  from the linked SPP proof. Xark's generic underconstraint analysis does not
  replace these protocol-specific checks.
- Verify native/browser commitment agreement, browser proof verification,
  circuit/key mismatch rejection, and supported worker configurations.
- Repeat the baseline benchmark protocol. Report before/after values and
  percentage changes, with changes in constraint form, key format, proof
  encoding, verification work, or concurrency identified alongside the results.

Deliverable: a behavior and performance comparison for the same escrow and
withdraw scenarios. Investigate regressions before extending the migration;
no numerical performance threshold has been agreed.

### 7 Complete the SDK migration and remove zk tools dependencies

- Apply the working integration to remaining SDK scenarios and standalone
  fixtures used by the Zolana build and verification commands.
- Remove obsolete generic derives, allocator code, prover/export hooks,
  feature forwarding, and generated client wrappers replaced by Xark.
- Check each feature set used by `zolana-program`, `zolana-macros`,
  `zolana-keypair`, and `zolana-transaction`, including native, WASM, and SBF.
  Keep compiler/prover dependencies out of on-chain builds.
- Run dependency checks and the relevant SDK, macro, example, WASM, and
  verifier suites. Update documentation and CI commands to match the final API.
- Remove `zk-tools` manifest entries and lockfile packages when their remaining
  consumers have migrated. Inspect the complete dependency graph rather than
  checking only `zolana-program`'s direct dependencies.

Deliverable: the migrated SDK and examples pass their checks, with no
`zk-tools` dependency in the program SDK's supported dependency graphs.

## Completion criteria

- Escrow and withdraw preserve their business rules and UTXO transaction flow;
  program-source changes are limited to imports, input declarations, annotations,
  and any necessary verifier integration.
- Xark supplies the generic input, compiler, witness-generation, and proving
  machinery. Zolana retains protocol-specific types and operations.
- Bounded inputs have fixed, checked encodings and canonical dummy padding.
- Protocol commitments and the application/SPP proof linkage remain identical.
- Both circuits prove natively and in the browser. Their proofs verify through
  the Solana program path, with adversarial cases covered.
- Before/after benchmark results and reproducible commands are saved.
- The supported SDK dependency graphs no longer include `zk-tools` crates.

## Source references

- [Xark at the selected development revision](https://github.com/blueshift-gg/xark/tree/b443d83ea8ec7f2253610887e9690623ad048aef)
- [Xark supported Rust subset](https://github.com/blueshift-gg/xark/blob/b443d83ea8ec7f2253610887e9690623ad048aef/docs/subset.md)
- [SDK circuit and transaction API](../../sdk-libs/program/README.md)
- [Escrow circuit](../../sdk-tests/timelock-escrow/program/src/circuits/escrow.rs)
- [Withdraw circuit](../../sdk-tests/timelock-escrow/program/src/circuits/withdraw.rs)
- [Native scenario benchmarks](../../sdk-libs/program/tests/scenarios/BENCHMARK.md)
- [Browser benchmark harness](../../sdk-libs/program/tests/wasm/tests/bench.spec.ts)

## Execution progress

- Native baseline complete: 56 scenario tests passed; measurements saved in
  `.claude/benchmarks/xark-migration/native-before.md`.
- Browser baseline complete: both benchmark cases passed. At 18 workers, the
  fixture medians for input preparation plus proving were 189 ms for escrow
  and 124 ms for withdraw. Raw logs and environment details are in
  `.claude/benchmarks/xark-migration/`.
- Built Xark 0.3.0 CLI at the selected revision; its cube tests passed.
- Added `sdk-libs/circuit` with Xark-backed values, bounded inputs, protocol
  Poseidon constants, and the initial UTXO/transaction port. Native hash parity
  passed for all 12 supported arities, byte packing, canonical fields, and
  checked amounts. The original SDK still uses zk-tools during this stage.
- The compiled padded-input fixture exposed an Xark frontend panic:
  `templates.rs:273`, invalid parent indices after input renumbering filters
  call regions. A focused fix and regression test are being validated in the
  local Xark checkout. The patch is recorded in
  `tools/xark/input-region-indices.patch` for reproducible tool builds.

## Implementation corrections from user review

- Replace the existing implementation directly. Do not keep a parallel Xark
  feature, parallel circuit modules, or checked-in escrow/withdraw wrapper
  packages. Compiler entrypoint packages belong under `target/` and are
  generated by the existing build command.
- Use native Rust `u64` (and other native integer widths) in program inputs and
  state. Xark supports checked integer arithmetic and input range checks.
- Use Xark `Field` directly. Remove the `CircuitVar` facade.
- Also prefer native `bool`, fixed byte arrays, Rust conditionals, Xark checks,
  Xark input macros, and ordinary execution helpers. Remove generic wrappers,
  the generic Circuit trait, allocators, and generated twin types. Keep the
  UTXO, owner, state commitment, and SPP transaction abstractions.

- The bounded input abstraction is named `ArrayVec` and lives in
  `sdk-libs/circuit/src/array_vec.rs`, as requested.

## Current state for draft review

This is an intermediate migration snapshot, not completion of the plan above.
The existing program SDK, macros, native escrow/withdraw programs and standalone
withdrawal now use Xark directly. The old zk-tools dependencies and primitive
facades have been removed from their manifests and implementation.

Native protocol and balance tests pass (8 tests), as do the standalone Xark
encoding, constraint mutation and compressed Solana proof tests (4 tests).
The escrow/withdraw test verifier keys have been regenerated for the port.
The before/after constraint comparison is recorded in
`../benchmarks/xark-migration/constraint-counts.md`.

Snapshot verification also rebuilt both timelock circuits and their test setup
keys, passed all 4 timelock functional tests (SOL/SPL proofs, SPP commitments,
invalid inputs and dummy-slot ordering), and passed `xtask check-deps`.

Remaining work includes the browser input-encoding integration, migration of
legacy SDK and macro tests, updating dependency rules/build recipes/docs, and
end-to-end SBF/browser validation. The last browser run had 4 passing and
6 failing tests, including nested-input name mismatches and a tampering fixture
still using the previous field naming. Final proof-time and memory comparisons
are pending. Test setup keys remain unsuitable for production.
