# 2026-07-26 00:35 UTC | the scope pass: which rows cannot close here, by design | queue-wide

- Baseline: HEAD `3cacdb4c`; the coordinator's framing correction, that programs and circuits are a standing constraint rather than a pending decision
- Worker: Opus 5 reconciliation subagent
- Explanation: I was asked to give a terminal disposition to each row that cannot close under the SDK-only rule, starting from three named candidates, and to produce the real denominator. The candidates did not survive checking: `T21`, `C08`, and `T23` are inside the branch.
- Evidence: read each candidate row against the code it names and against `authority-rulings.md` at this HEAD; grepped the 49 open rows for references to `programs/`, `program-libs/`, `prover/`, and circuits and read each hit.

## The three candidates, and why none of them is terminal

- Verdicts: `PARTIAL` for `T21`, `DIVERGENT` for `C08`, `DIVERGENT` for `T23`, each moving to `needs_fix`

`T21` and `C08` were ruled on at `3cacdb4c`, which landed about an hour before I looked. The `T21` ruling leaves `program-libs/interface` truncating and puts the loud guard in both SDKs, so the work is a guard in `sdk-libs/transaction` matching one TypeScript already has, plus the boundary vector neither language holds. The `C08` ruling says so in as many words, and corrects the coordinator by name: the rail-inference defect is in `sdk-libs/client/src/prover/proof.rs`, an SDK crate, and no program or circuit is involved.

`T23` I checked myself. The specification conflict is settled by the amendment at `1d6b9873`, which described the implementations rather than changing them, and the residual is a strictness difference between `internal.ts:117`, which refuses a field input at or above the BN254 modulus, and `spp_proof_inputs.rs`, which range-checks nothing. Both files are in `sdk-libs`. It comes off `BLOCKED` because evidence can now decide it, and it decides against Rust.

So the terminal set is empty at row level. That is worth stating plainly rather than softening, because it is the opposite of what the queue looked like this morning: the rows that appeared to be waiting on the protocol were waiting on a ruling, the rulings arrived, and each one pointed back into the branch.

## What replaced the category I was asked to create

Rather than a terminal verdict, the scope pass produced a denominator, recorded in [scope-and-denominator.md](../scope-and-denominator.md). The distinction that matters for the entry criterion is not SDK against non-SDK but decided against undecided: 41 of the 49 open rows are ordinary work, 4 are dispositions needing a confirming artifact, and 4 are pinned on a decision whose fix is in scope either way.

I also gave the two protocol defects the disposition the coordinator asked for, since they are the items genuinely outside: `PD-2` took the separate pull request and merged at `a811b20e`, which is the precedent, and `PD-1` has not been routed anywhere and is a liveness risk rather than an accepted limitation. Recommending the route is as far as I go; choosing it is the owner's.

- Gap and smallest fix: `T21` owes the Rust guard and the boundary vector; `C08` owes the rail argument in `proof_from_gnark_json`; `T23` owes the range check in `spp_proof_inputs.rs`
- Row transitions: `T21` `needs_re_review -> needs_fix`, verdict unchanged; `C08` `needs_re_review -> needs_fix`, verdict unchanged; `T23` `BLOCKED -> DIVERGENT` and `needs_re_review -> needs_fix`
- Progress: `90/145` unchanged, since no row closed
- Exact next file: none waiting; the oracle-strength audit of the 90 `PARITY` rows resumes next
- Full SDK parity claim: unsupported
