# Circuit proof recheck — 2026-10-10

Subsequent branch review: [ECIES std proof completion review](/Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/ecies-std-proof-review.md). Commit `c255c6400` adds the KDF and full 40-byte/context envelope composition that was still missing in this earlier recheck.

Source: `/Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514`, HEAD `a2b339b6ae18123c67123b0c1d5235d835f428bc`. Static review of the changes since `52a71cb723ebeb266d34e82867050192e8126240`, with independent GPT-6.1 Sol reviews of the revised ladder and new AES composition. No tests, builds, Lean execution, generators, or mutation experiments were run. Proof infrastructure remains excluded.

## Do these proofs make sense and catch bugs?

**The current P-256 and one-block AES statements impose meaningful correctness obligations.** They take the actual extracted constraint predicates as premises and conclude equality with mathematical specifications. They do not simply assume the desired multiplication or ciphertext result.

If faithful extraction includes a circuit change, the specification and assumptions remain fixed and consistent, and Lean successfully checks the theorem, the circuit cannot admit a counterexample to that theorem. A change admitting an incorrect output therefore cannot retain a valid proof of the same statement. A source-only review cannot establish that the current proof terms actually pass Lean.

| Change | What the current statements establish |
| --- | --- |
| P-256 constraints allow an accepted point other than `sQ` | Contradicts `scalarMulChecked_sound` under its input bounds, on-curve and lookup hypotheses. The top-level agreement proof establishes the relevant input properties. |
| AES key recurrence, round wiring, counter placement or ciphertext binding admits an incorrect output | Contradicts `AesCtr_sound` for its 32-byte key, 12-byte nonce and 16-byte plaintext specialization, under lookup semantics. |
| A new constraint rejects valid inputs, or makes the entire circuit unsatisfiable | Not excluded by these soundness implications. Acceptance implies correctness can hold even when nothing is accepted. |
| A production lookup argument is unsound | Not excluded by a theorem that assumes ideal lookup semantics. |
| An error affects later CTR blocks, the partial tail, KDF, or envelope composition | Not covered by the new single-block AES theorem alone. |

These are reasoned consequences of the theorem statements, not observed mutation-test results. Some proof scripts can also break after harmless refactors; proof failure is not by itself evidence of a circuit bug.

## What changed since the expanded review

**The old P-256 inverse-four rejection mechanism has been removed.** [ladder.go:138][ladder] assembles the low-bit corrections on the target side. For the previously problematic decomposition `u=1, d=4, ε=-1`, the target is `4R=-Q`, and the discarded addition now computes `R+4R`, whose operands have distinct x-coordinates in the prime-order group. It no longer unconditionally compares the accumulator's x-coordinate with Q's. This addresses the reported mechanism; it is not a proof that all valid inputs, all intermediate guards, or all hint executions succeed.

The public [scalar-multiplication theorem][scalar] retains the same conclusion and assumptions. Its new target-side group equations are derived from the extracted guarded additions, Boolean selections and final coordinate assertions in `ScalarMul.lean`; they are not newly assumed at the top level. [ladder_close][closing] rearranges those equations into the same relation needed for denominator cancellation.

**The single-block AES proof gap is now closed at the source-statement level.** [Sound.lean:45][aes] takes `AesCtrBlock_32_12_16_16 Key Nonce Plaintext Ciphertext` and concludes byte-valued inputs/output and equality with `Spec.ctrEncrypt`. [CtrBlock.lean:17][aesbridge] unfolds the extracted predicate and composes the key expansion, nonce/plaintext checks, cached first round, later rounds, final round and all sixteen output equalities. Intermediate helper premises about the expected state are discharged from the independent specification; they are not assumptions granting encryption correctness.

**The Merkle exception remains.** [Main.lean:18][hash] still globally assumes injectivity of a finite-field compressing hash. That is inconsistent, so the theorems relying on it cannot serve as meaningful guarantees for concrete Poseidon. P-256 and the AES proof chain do not depend on that `Main` axiom.

No new concrete wrong-output acceptance defect was identified in this focused recheck. Lookup assumptions, mathematical parameter axioms and unproved completeness remain explicit limits. The earlier AES/KDF/envelope findings must now distinguish the completed one-block AES theorem from the still-unproved larger compositions.

[ladder]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/verifiable-encryption/p256/emcurve/ladder.go:138
[scalar]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/ScalarMul.lean:29
[closing]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/LadderEnd.lean:167
[aes]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Aes/Sound.lean:45
[aesbridge]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Aes/CtrBlock.lean:17
[hash]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/Main.lean:18
