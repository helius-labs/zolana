# 2026-07-25 22:00 UTC | wallet and merkle batch, the two hasher rows only | `program-libs/hasher/`

- Baseline: HEAD `4545e740`; the batch merged as `4545e740`, carrying `a4560f41` and `4d9a39f1`
- Worker: reconciliation subagent, cut off mid-pass; entry completed and committed by the coordinator from the row text the subagent had already written
- Explanation: This is a partial fold-in, and saying so matters more than the two rows it closes. The subagent verified the batch's evidence and had finished rewriting `H01` and `H04` when its environment went down. `M01`, `M02`, and `W04` were untouched and stay as they were. Nobody should read the batch as folded in.

## Two rows close

- Verdicts: `PARITY` for `H01`, `PARITY` for `H04`

`H01` closes because the fifth Poseidon copy is fixed. The row had four of five TypeScript
reimplementations matching `zolana-hasher` byte for byte, with `client/src/internal.ts` still
carrying a sixteen-entry `PARTIAL_ROUNDS` table, so the client would hash 13 to 16 inputs where
`Poseidon::hashv` returns `InvalidWidthCircom` and no chain can reproduce the digest. The table is
now the twelve entries Rust has, the arity lookup throws above it, and the client gained the
Poseidon parity suite it was the one package to lack. The five copies now stop where Rust stops.

`H04` closes because the second owner of `bigint_to_be_bytes_array` is fixed. `merkle-tree` had
been corrected and `keypair/src/bytes.ts` left truncating, which is why the row was held at
`PARTIAL`: a row cannot be parity while half its named owner carries the defect the row is about.
`keypair` now refuses what `BigUint` cannot represent, throwing through the package's own
`invalidLength` helper and reporting width `-1` for a negative as `checkedBytes` does.

Both fixes were made by a different worker than the reviewer who found them, which is what the fix
workflow asks for and did not happen the first time either defect was recorded.

## What this entry does not close

`M01` and `M02` carry the Merkle oracle the batch generated, and nobody has judged it. `W04` is
reported `PARITY` by the batch on a 28-case oracle over `create_withdrawal` and `create_split`,
and the subagent recorded a disagreement before it stopped: the row's signing findings in
`private-transaction.ts` are fixed only as far as reading shows, and this branch has already
produced one false parity claim on exactly that basis. `W04` stays open until an executed
comparison covers the signing path, not because the batch is suspected of error but because
reading is not the standard this queue uses.

- Exact next file: `planning/typescript-sdk-port/row-updates/wallet-misc.md`, rows `M01`, `M02`, `W04`
