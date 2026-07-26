# 2026-07-26 01:50 UTC | client batch B's residual: five rows close, one claim declined | C07, C08, C15, C19, C20, T23

- Baseline: HEAD `ecfda044` on `port/reconcile`; checklist last edited at `9effd51a`
- Worker: reconciler, taking the role over after the previous holder was dropped mid-tool-call
- Explanation: [row-updates/client-b.md](../row-updates/client-b.md) was folded in part at `1b10b87c`, which closed seven rows. Six of the rows it covers were left unreconciled. This entry folds those six.
- Evidence: read each claim against the code and the test it names at `ecfda044`, then ran the named replays. `npm run build` first, because `@zolana/hasher` resolves through `dist/` since the Poseidon repackaging and the six client test files cannot collect without it. That failure shape is worth naming, since it looks like the worktree hijack the plan warns about; the branch was checked before anything was cleared and read `port/reconcile`.

## What was reproduced here, and what was taken on report

The batch reports control edits applied and observed to fail. Those were not re-applied. What was checked directly: that each cited test exists, that it covers what its row is about, and that it passes. The 6 client test files hold 135 assertions and pass at `ecfda044`; the workspace suite is 92 files and 1684 tests, of which 91 files and 1683 tests pass and 1 of each is skipped.

The distinction matters most on `C19`, where it works in the batch's favour. Its oracle did not merely pass, it caught two divergences on first contact that the previous by-eye reading had missed, both in how a `completed` status carrying nothing useful is reported. A test that finds a real difference the moment it is written is the evidence class this queue has been asking for.

## The declined claim

`T23` is the one to check, because nobody else will. The batch heads a section `T23 residual, canonical coordinates` and marks it `PARITY`. The work is real, but it is in `sdk-libs/client/src/prover/proof.rs`, hardening `hex_to_be_32` so the gnark proof parser reads a coordinate canonically. `T23` is about `spp_proof_inputs.rs`, which builds the proof inputs sent to the prover. The two run in opposite directions: one is how a returned proof is read, the other is whether a caller's field value is range-checked before a proof is made over it.

At `ecfda044` `spp_proof_inputs.rs` still names the modulus once, at `modulus() - magnitude` on line 35, to wrap a negative amount. It range-checks nothing. `internal.ts:95` still refuses a value at or above `BN254_MODULUS`. The difference the row records is untouched, so the row keeps `DIVERGENT`. The parser work is credited on `C08`, where the file belongs.

Two rows in one commit describing "canonical" handling of a BN254 value is how this happened, and it is worth naming so the next reader does not repeat it.

- Verdicts: `PARITY` for `C07`, `C08`, `C15`, `C19`, `C20`; `DIVERGENT` unchanged for `T23`
- Gap and smallest fix: `T23` owes the range check in `spp_proof_inputs.rs` and a boundary vector in both languages, `modulus - 1` accepted against `modulus` refused
- Row transitions: `C07` `needs_fix` to `done`, `PARTIAL` to `PARITY`; `C08` `needs_fix` to `done`, `DIVERGENT` to `PARITY`; `C15` and `C20` `needs_fix` to `done`, `PARTIAL` to `PARITY`; `C19` `needs_re_review` to `done`, `PARTIAL` to `PARITY`; `T23` unchanged
- Progress: `95/145`, from `90`
- Exact next file: the hasher and merkle batch's residual, then the zone-authority shape finding against `C18`
- Full SDK parity claim: unsupported
