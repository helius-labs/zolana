# 2026-07-25 20:45 UTC | program-libs coverage batch folded into the table | `program-libs/{event,hasher,indexed-array,user-registry-interface}`

- Baseline: HEAD `59515aed`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none new this entry`
- Worker: Opus 5 reconciliation subagent, folding [row-updates/program-libs-coverage.md](../row-updates/program-libs-coverage.md); batch merged at `bdb9c9da`
- Explanation: The batch that covered the 27 rows the queue had never admitted recorded its outcomes in its own row-updates file, because batch workers must not edit `review-checklist.md`. This entry moves them into the table. It is not a relay: the rows below close on artifacts I read and a suite I ran, and where the batch's report and its artifacts disagree, the artifacts decide and the row stays open.
- Evidence: `xtask/src/bin/program-libs-parity.rs` reads the four crates directly and emits `sdk-libs/ts/vectors/program-libs-parity-v1.json`, which regenerates with `--check`. The 119 tests are in `interface/test/vectors/program-libs-event.test.ts`, `transaction/test/vectors/program-libs-event.test.ts`, `merkle-tree/test/vectors/program-libs-hasher.test.ts`, and `wallet/test/vectors/program-libs-registry.test.ts`. I ran `npx vitest run` over `keypair`, `interface`, `merkle-tree`, `wallet`, and `transaction`: 38 files, all passing, including every one of those four. I read the fixture's `userRegistry.pdas` block and `wallet/test/registry.test.ts` to settle where `R01`'s derivation evidence actually lives.

## Fourteen rows close on parity

- Verdicts: `PARITY` for `E01`, `E02`, `E04`, `H02`, `H03`, `H06`, `H07`, `D01`, `D02`, `D03`, `D04`, `R01`, `R02`, `R03`

Each cell names the test that backs it. Three of the fourteen carry a recorded gap that does not bear on parity, because the Rust surface in question has no TypeScript counterpart and no SDK caller: `Sha256BE` under `H02`, the `Hasher::ID` discriminants under `H07`, and five unused user-registry instruction builders under `R03`. Their values are pinned in the fixture, so a later port has its oracle already written rather than an absence to argue from.

`R01` closes on evidence the batch did not claim. Its own tests cover the program id, the seed, and the key widths, and its report lists the four Rust `user_record_pda` derivations under "pinned in the fixture but not compared against a TypeScript implementation, because none exists". A TypeScript implementation does exist, `userRecordAddress` in `wallet/src/registry.ts`, and `wallet/test/registry.test.ts` checks it against the wallet fixture's `recordPda` and `canonicalBump`, which is `W07`'s evidence. So the derivation is compared, just not next to the definition it comes from.

## Six recorded dispositions become confirmed ones

- Verdicts: `NOT_APPLICABLE` for `H09`, `H10`, `H11`, `H12`, `H13`, `H14`

The coverage audit left nine dispositions at `needs_re_review` and flagged its own reasoning on seven of them, because they rested on nobody having called the Rust code rather than on anything positive. This batch answers that for the four `zero_bytes` rows and the module above them: all 41 entries of each of the three Rust zero tables are reproduced by the TypeScript runtime construction, 123 values in total, and an empty `CoreMerkleTree` at five heights lands on the table entry for that height. That converts a plausible adaptation into a demonstrated equivalence, which is exactly what the audit asked for.

`H09` and `H10` are the two the audit did not undercut, and they close on their own reasoning rather than on new work. Solana BPF syscalls exist only inside the Solana virtual machine, and the SDK compiles the path where they are not reachable. That is a platform fact a reader can check, not an inference from silence.

## Seven rows stay open, four of them against the batch's own count

- Verdicts: `PARTIAL` for `H01`, `H04`, `H05`
- Verdicts: `NOT_APPLICABLE` for `E03`, `E05`, `E06`, `H08`

The batch reports 17 `PARITY`, 1 `FIXED`, and 9 `NOT_APPLICABLE`. Its own row tables hold 16, 1, and 10: the report notes that `event/src/output_utxo.rs` moved to a disposition against the audit's prediction and did not carry that through its spread table. Four further rows do not close on the artifacts:

`H01`. The four TypeScript Poseidon copies this row named match `zolana-hasher` byte for byte across 312 tests. A fifth copy at `client/src/internal.ts:26` still carries the over-wide 16-entry `PARTIAL_ROUNDS` table and will hash 13 to 16 inputs, which `Poseidon::hashv` rejects and the `sol_poseidon` syscall caps at 12, so any digest it produces is unverifiable on chain. It is the same Rust behaviour and now sits in this row's owners. The fix is one line and is held only because another worker owns that file.

`H04`. The batch found the one real divergence of its 27 rows here, in `merkle-tree/src/bytes.ts`, and fixed it. The row's other named owner, `keypair/src/bytes.ts`, has the same silent truncation and was left. A row cannot be parity while half its TypeScript owner carries the defect the row is about, and the fix is the reviewer's own, which step 8 of the fix workflow does not accept as closing evidence.

`H05`. `create_hash_chain_from_slice` is ported twice and now verified. `create_two_inputs_hash_chain`, the other half of the file's public surface, is ported nowhere and has seven Rust callers on the proof path. It is not a fold of the single-input chain, so a port that reached for `hashChain` twice would compute different values. The batch routed this to a new `@zolana/client` row; the missing function is inside this row's canonical Rust source, so it belongs here.

`E03`, `E05`, `E06`, and `H08` keep the `needs_re_review` the earlier reconciler gave them. `H08` is the one flagged disposition the batch did not strengthen: it repeats "no SDK caller in Rust or TypeScript", which is the argument the audit called weak. `E05` and `E06` are restatements with no artifact, and `E05`'s spec divergence is still open. `E03` is a new disposition and it comes with a live finding rather than a clean absence: the TypeScript `OutputUtxo` is unreachable, with no codec, no importer, and no entry in the export test, so it is a shape that reads as coverage and is not.

- Gap and smallest fix: `H01`, truncate the client `PARTIAL_ROUNDS` table to 12 entries. `H04`, apply the `merkle-tree` overflow rejection to `keypair/src/bytes.ts`. `H05`, port `create_two_inputs_hash_chain` against the four fixture vectors, or record why the TypeScript prover path does not need it. `E03`, decide whether the unreachable type is published surface
- Row transitions: `todo -> done` for `E01`, `E02`, `E04`, `H02`, `H03`, `H06`, `H07`, `D01`, `D02`, `D03`, `D04`, `R01`, `R02`, `R03`; `needs_re_review -> done` for `H09`, `H10`, `H11`, `H12`, `H13`, `H14`; `todo -> needs_fix` for `H01` and `H05`; `todo -> needs_re_review` for `E03` and `H04`; `E05`, `E06`, and `H08` unchanged
- Progress: `19/145` after this entry; the `program-libs` set is `20 of 27` closed
- Exact next file: `I01 program-libs/interface/src/error.rs`
- Full SDK parity claim: unsupported. Twenty of the 27 `program-libs` rows are now closed on artifacts, and the interface and keypair batches are folded in separate entries
