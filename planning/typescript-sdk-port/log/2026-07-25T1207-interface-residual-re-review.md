# 2026-07-25 12:07 UTC | interface residual re-review | `program-libs/interface`

- Baseline: source snapshot `14ad30017ef5b512548f65284eae0212684d8197`; recorder HEAD `2429244a29fd8f3193ec664e651d0de9392215ee`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only residual re-review; implementation commits `484ac5ed` through `14ad3001`
- Explanation: The residual review covered canonical interface hashes, PDAs, merge prefixes, instruction routing, current-Rust oracles, exports, and aggregate inheritance.
- Evidence: I03, I04, I08, I09, I11, I12, I15, I17, I20, I21, I24, I25, and I27 now have canonical hash, PDA, prefix, routing, rejection, and current-Rust oracle evidence. Reported gates passed: 29 Rust interface tests; 385 TypeScript tests with 1 skipped; browser, API/export, dependency, package, and focused package checks. These checks were not rerun by the recorder.
- Verdict: the 13 named rows are `PARITY`; I07, I10, I19, I22, I26, I28, I29, and I37 are `BLOCKED`
- Gap and smallest fix: Resolve the deposit and protocol-config authority conflicts for blocked children. The legacy frozen-revision fixture gate remains package-wide bookkeeping rather than scoped evidence-blocking; preserve the stale `CURRENT_RUST_INTERFACE_FIXTURE.sourceCommit` for the fixture-gate worker.
- Row transitions: 13 rows `needs_fix -> done`; I26 `PARTIAL -> BLOCKED`; I28 `DIVERGENT -> BLOCKED`; I29 and I37 `PARTIAL -> BLOCKED`
- Progress: `31/118`; package `28/37`
- Exact next file: `T15 sdk-libs/transaction/src/wallet/sync.rs`
- Full SDK parity claim: unsupported; interface protocol children and other package rows remain adverse
