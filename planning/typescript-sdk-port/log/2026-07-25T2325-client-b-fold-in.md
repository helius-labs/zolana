# 2026-07-25 23:25 UTC | client batch B, the three zone rails and the merge oracles | `sdk-libs/client/src/prover/`

- Baseline: HEAD `9f9d6676`; oracles `client/test/oracles/zone-v1.json` and `merge-v1.json`; batch commits `2f2654f1`, `6de00db6`, `889262d5`, `778747a1`, `07ce3376`
- Worker: Opus 5 reconciliation subagent, judging [row-updates/client-b.md](../row-updates/client-b.md) against the tree
- Explanation: Seven rows close, which is the largest single fold in this queue, and the reason is that the batch stopped arguing and started generating. Its rule was stated up front and kept: where a control edit is not recorded, the row is not `PARITY`. Four control edits are recorded for the zone rows with the count of assertions each broke, which is a claim that can be checked and would be embarrassing if invented.
- Evidence: `sdk-libs/client/src/prover/ts_zone_oracle.rs` and `ts_merge_oracle.rs` run the production `ZoneTransferProver`, `ZoneAuthorityProver`, and `MergeProver` and the `pub(crate)` serializers, and write the committed oracles; each generator has a currency test that fails when the committed file is stale unless `ZOLANA_UPDATE_TS_ORACLES=1` is set. I read both generators to confirm they call production code rather than reimplementing it. I ran `npx vitest run` over `zone-oracle.test.ts`, `merge-oracle.test.ts`, `two-inputs-hash-chain.test.ts`, and `circuit-types.test.ts` at this HEAD: 80 tests, passing.

## The generators are not under `xtask`, and that was the right call

The brief asked for `xtask`. The serializers these rows exist to pin, `to_json_merge`, `to_json_merge_zone`, `to_json_zone`, `to_json_p256_zone`, and `to_json_zone_authority`, are each `pub(crate)`. An `xtask` binary can reach them only if that visibility widens, which would enlarge the Rust public API to serve a test. The batch put `#[cfg(test)]` generators in the crate instead and produced the same artifact, a committed fixture replayed by TypeScript. `C09` had recorded the visibility problem as a blocker and named widening the API as the smallest fix; this is the better answer to the same problem.

## I verified the replacement property test myself, by control edit

The old `circuit-types.test.ts` enforced a deferral the owner has withdrawn, so it had to change, and a test that changes to accommodate the code it guards deserves a look. The replacement pins the reachable set in both directions. I confirmed it discriminates rather than reading it:

- Renaming `"transfer-zone-authority"` in `client.ts` so the rail is no longer reachable: the exact-seven case fails, naming the missing circuit.
- Adding `"address-append"` to the circuit map: the forester case fails, naming the file.

Both edits were reverted and the worktree is clean. One limit worth recording, since it is the difference between what the test does and what a reader might assume: it discriminates across the eight circuit types Rust declares. A TypeScript file inventing a ninth string outside that set would not fail it.

## Three zone rails close, under a withdrawn deferral

- Verdicts: `PARITY` for `C13`, `C14`, `C18`

[row-updates/zone-prover-ruling.md](../row-updates/zone-prover-ruling.md) records the disposition change and claims no verdict, correctly. The rails are compared over the ten supported shapes each, values and serialized request bytes, 66 assertions in total. What makes this stronger than a shape sweep is that each rail has a test aimed at the way it could be wrong while still matching a digest: the zone-authority rail is checked against the zone transfer over identical inputs, asserting the private transaction hashes match while the public input hashes do not, and the P256 rail is checked for owner identities staying out of the hashed chain while the shared signing field stays a private input. The four control edits break 21, 21, 21, and 62 of the 66.

Two hazards are recorded rather than guarded, and both would have been the over-strict failure this queue keeps finding if either had been fixed in TypeScript alone. Rust's zone provers accept `zone_program_id: None` and turn it into a literal zero, leaving a proof bound to no zone, where the TypeScript signature requires an address. Rust resolves zone-authority requests against the ten supported shapes while four zone-authority verifying keys exist, so Rust will build a 2x3 request the prover server cannot serve. Each needs one change to both languages.

## Four more rows close on the same oracles

- Verdicts: `PARITY` for `C09`, `C16`, `C17`, and `H05`

`C09` closes on exact request bytes for both merge rails plus thirty zone bodies, compared key order included, which caught the TypeScript P256 request interleaving its fields differently from the Rust struct. `C17` closes on the merge values it had been waiting for. `C16` I closed on the same oracle although the batch did not claim it, because `merge-oracle.test.ts` drives this row's own entry point, `assembleMergeWithProofs`, and compares its ten named values against Rust; that also gives `assembleMergeZoneWithProofs` its first exercise, one of the eight consumerless exports the completeness audit catalogued.

`H05` closes on the correction rather than on the work. The row claimed `create_two_inputs_hash_chain` had seven Rust callers on the proof path. It has none: the audit searched, the batch searched again, and the seven are callers of the single-input chain that was already ported. The real residue was that `xtask` committed vectors nobody read, and the batch ported the function and replayed them.

## Rows advanced, still adverse

- Verdicts: `PARTIAL` for `C06`, `C07`, `C19`, `C21`, `C22`

`C19` is the one I held against the direction of travel. Its missing entry points drop from six of eight to one, and that one is absent by ruling. But its nine polling behaviours are TypeScript expectations that a reader matched to the arms of Rust `poll_async`, and that is the kind of evidence 35 of 36 earlier `PARITY` verdicts died of. Generating the poll arms from Rust closes it.

`C07` gets the owner's ruling written into it and stays adverse, because the ruling says to withdraw `batchUpdateNullifierTreeInstruction` from the public surface and the withdrawal has not happened. A decision is not an implementation.

`C21` picked up three more orderings from a read-only re-audit, each one changing which error a caller branches on without changing what is accepted, which is precisely what an accept-and-reject suite cannot see.

- Gap and smallest fix: `C07`, remove the forester builder from the public surface and record it. `C19`, generate the poll arms from Rust. `C22`, one line in `public-exports.md`. `C15`, `C17`, and `C20` share one `xtask` defect, an `inventory.json` that names three files the package does not ship
- Row transitions: `MISSING -> PARITY` for `C13`, `C14`, `C18`, each `proposed -> committed`; `PARTIAL -> PARITY` for `C09`, `C16`, `C17`, `H05`; `DIVERGENT -> PARTIAL` for `C22`; `needs_re_review -> needs_fix` for `C07`, which now has a named implementation task; evidence recorded on `C06`, `C19`, and `C21`
- Progress: `74/145` after this entry
- Exact next file: [row-updates/quality-and-completeness-audit.md](../row-updates/quality-and-completeness-audit.md) for `E03`, then [row-updates/keypair-error-redaction.md](../row-updates/keypair-error-redaction.md) for `K10`
- Full SDK parity claim: unsupported
