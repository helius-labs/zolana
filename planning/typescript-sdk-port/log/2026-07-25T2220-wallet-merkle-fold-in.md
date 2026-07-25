# 2026-07-25 22:20 UTC | wallet and merkle batch, the three rows the partial fold-in left | `sdk-libs/merkle-tree/`, `sdk-libs/wallet/`

- Baseline: HEAD `2aa59788`; fixtures `merkle-semantics-v1.json` and `wallet-actions-v1.json`, both generated from the crate and committed
- Worker: Opus 5 reconciliation subagent, completing the pass that [2026-07-25T2200](2026-07-25T2200-wallet-merkle-fold-in-partial.md) left unfinished when its predecessor's environment went down
- Explanation: The earlier entry closed `H01` and `H04` and said plainly that `M01`, `M02`, and `W04` were untouched. These are those three. Two move, one does not, and the one that does not is the row the batch itself reported at `PARITY`.
- Evidence: I ran `npx vitest run` over `merkle-tree/test/vectors/merkle-semantics.test.ts` and `wallet/test/vectors/wallet-actions.test.ts` at this HEAD after `npm run build` and clearing `node_modules/.vite`, as the README's stale-`dist` note requires. Both pass, 103 tests together with the transaction oracle. I read `xtask/src/bin/merkle-semantics.rs` and `xtask/src/bin/wallet-actions.rs` to confirm the fixtures come from the Rust crates rather than from a TypeScript recording, and I searched `sdk-libs/ts/wallet/test` for any exercise of the signing path against Rust, which is what decided `W04`.

## `M01` closes on an executed trace

- Verdict: `PARITY` for `M01`

This row was reopened because a differential oracle contradicted it, so a reading could not close it and an executed comparison had to. The fixture records a trace rather than an end state, and that shape is the point: atomicity is a property of a sequence of calls, and a fixture holding one final root cannot tell "the rejection left the tree alone" from "the rejection happened to land on the same root". Each step carries the outcome of the call and the observable state after it.

The direction of the fix deserves to stay legible, because the row is now parity with a Rust that this branch changed. `4d9a39f1` corrected `get_non_inclusion_proof`, which returned a proof that `verify_non_inclusion_proof` rejected on the same tree; the exclusion ranges tile `(0, highest_value)`, so a proof at the sentinel is not representable and Rust was internally inconsistent rather than merely more permissive. The TypeScript guard was not relaxed, which is what step 6 of the fix workflow required. A reader comparing against `origin/main` will still see the old Rust behaviour.

## `M02` moves off `BLOCKED` without closing

- Verdict: `PARTIAL` for `M02`

`BLOCKED` recorded that the evidence then available could not settle the row. The three plain-tree traces settle its behavioural half: the next index carries no root-history offset, the history root index counts root updates modulo the history length and wraps rather than staying at zero, a refused append and a refused update leave the root, leaf count, next index, history length, and sequence number byte-identical, and a tree with no history rejects both accessors instead of answering with a default.

It stays open because it is a crate-root row and therefore also claims the export, browser, and package-contents surface. Those three still rest on the relayed P06 report the parity evidence audit reopened this row over, and the packed-artifact gate fails for this package on `globalThis.process`, the cross-cutting defect recorded on `K13`. A behavioural oracle cannot reach any of that.

## `W04` is held adverse against the batch's own report

- Verdict: `PARTIAL` for `W04`

The batch reported `PARITY` on a 28-case oracle. The oracle is real and it does close half the row: the strictness regression that made `W04` divergent is confirmed from the crate rather than from a reading of it, because Rust records a zero-amount withdrawal as `{"arm": "ok"}` and the port now agrees.

The other half is the four clauses the row was originally filed on, and the four are about signing: which rail `applyP256Signature` selects, and how much of the note `matchingInput` re-checks between create and sign. They were judged closed by an independent reader comparing `private-transaction.ts` with `transaction.rs`, and that reading looks right to me too. It is still not the standard this queue uses. `wallet-actions-v1.json` carries no `apply_p256_signature` or `validate_unsigned_inputs` case, and the one TypeScript exercise of the path, `wallet/test/wallet.test.ts:335`, asserts against a TypeScript expectation. Thirty-five of thirty-six earlier `PARITY` verdicts died of exactly this, and the cost of re-litigating that audit is why the bar does not bend for a claim that happens to be plausible.

- Gap and smallest fix: `M02`, rerun the export, browser, and package gates against a named commit, and resolve the packed-artifact failure with `K13`. `W04`, add rail-selection and substituted-input cases to `xtask/src/bin/wallet-actions.rs` and replay them through `signPrivateTransaction`
- Row transitions: `needs_fix -> done` for `M01`; `BLOCKED -> PARTIAL` for `M02`, status unchanged at `needs_re_review`; `DIVERGENT -> PARTIAL` for `W04`, status unchanged at `needs_re_review`, because the conflict it named is resolved and what remains is a missing test class rather than a disagreement
- Progress: `61/145` after this entry
- Exact next file: `planning/typescript-sdk-port/row-updates/transaction-parity.md`, rows `T01` through `T31`
- Full SDK parity claim: unsupported
