# Static review of the Lean formal verification

Latest status: [2026-10-10 circuit recheck](/Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/lean-circuit-recheck.md), covering the revised P-256 correction and newly completed one-block AES proof.

Follow-up: the [expanded circuit review](/Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/lean-circuit-review.md) found a concrete P-256 valid-input rejection at scalar `4⁻¹ mod n`, superseding this initial pass's statement that no specific failing input had been identified. The follow-up includes the newer AES files and excludes proof infrastructure.

Reviewed source: `/Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/`.

Revision inspected: `52a71cb723ebeb266d34e82867050192e8126240`, including the untracked `Aes/KeyExpansion.lean`, `Aes/KeySpec.lean`, and `Aes/KeySteps.lean` files present in that worktree. Review date: 2026-10-09.

This was a source-only review. No Lean elaboration, builds, tests, solver runs, extraction, or parameter regeneration were performed. The directory contains approximately 236,000 lines across 188 Lean files. I inspected theorem statements, assumptions, import dependencies, critical arithmetic and group-law arguments, representative generated proof/constraint modules, the extractor, and relevant production callers. This is not a claim to have manually verified every generated line or established that the submitted proofs compile.

## P-256 assessment

The P-256 development is substantially connected to the extracted circuits. Its main statements are conditional soundness results: if the extracted constraints hold, the returned point equals the corresponding scalar multiplication in Mathlib's actual Weierstrass point group. I did not identify an additional concrete arithmetic soundness defect in the P-256 arguments inspected. The most immediate actionable problem is that the default build and CI omit this library entirely, described in finding 1.

The contradictory Poseidon assumption in finding 2 is **not** in the P-256 theorem import chain. Static traversal of the local imports of `AgreeKey` and `DerivePublicKey` reaches 169 local modules, excludes `Main`, and finds four explicit local axioms: BN254 scalar-field primality, P-256 base-field primality, P-256 order primality, and annihilation of every P-256 point by that order.

### What the P-256 statements actually cover

| Component | Connection and conclusion | Assessment from source |
| --- | --- | --- |
| Variable-base multiplication | [`scalarMulChecked_sound`][scalar] takes `ScalarMulChecked_8_8_8_h903d3456 … k` and returns an on-curve point equal to `S.value • mkPoint hQ`, preserving `k`. | Direct reference to the extracted predicate, not merely a hand-written multiplication model. Input point validity and limb bounds are explicit preconditions. |
| Fixed-base multiplication | [`scalarMulBase_sound`][base] takes `ScalarMulBase_8_hd39a5e0e … k` and concludes `mkPoint hR = S.value • G`. | The generator is the concrete P-256 generator. The result is not defined to be whatever the circuit computes. |
| Key agreement | [`agreeKey_sound`][agree] takes `AgreeKey_32_65_6 sk pk packed`. It establishes the recipient's prefix and canonical coordinates, the ECDH and ephemeral point equations, and all six packed outputs. | The proof constructs bounded elements from the byte checks, invokes both multiplication proofs, and checks canonical output packing. The caller discharges the important multiplication preconditions. |
| Public-key derivation | [`derivePublicKey_sound`][derive] takes `DerivePublicKey_32_32 sk X lo hi`. It establishes `sG`, canonical output coordinates, output byte bounds, compressed packing, and `n ∤ s`. | Covers rejection of zero modulo the group order as a consequence of an accepted witness. It does not require the original 32-byte scalar to be less than `n`; its semantics are multiplication by that integer, hence reduction modulo `n`. |
| Field arithmetic | [`Instances_1.lean`][instances] derives generic arithmetic relations from extracted `CheckPolynomial` definitions; [`checkPolynomial_core`][plain] lifts them to integer congruences with range/carry bounds. | There is an explicit bridge between emitted constraints and certificate-based arithmetic. The per-call modulus, input bounds, and continuation matter; the certificates alone are not the entire argument. |
| Production entry points | [`formal/ve/circuits.go`][wrappers] invokes `p256.ComputeKeyAgreement` and `p256.DerivePublicKey`. [`emcurve/gadgets.go`][gadgets] routes extraction through wrappers rebuilding the same operations from limbs and bound metadata. | A meaningful source connection exists for these fixed-layout gadgets. This does not establish a theorem about the entire production merge circuit or its verifying key. |

### Critical P-256 arguments traced

- **The product hint is not trusted.** In [`ScalarMul.lean`][scalar], the product's limbs are reconstructed from checked pieces, its curve equation is derived, and the ladder relation binds it to the scalar. The final argument is not an equality assumed about `p256ScalarMulHint`.
- **The rational denominator cannot disappear.** [`ScalarMul.lean:192`][den] derives its positivity from the nonzero bit sum. At lines 930–932, the 129-bit bound gives `den < n`. [`Ladder.ladder_chain`][chain] then uses coprimality with prime `n` to cancel the denominator in the point group. Allowing `den = 0` would invalidate this argument; that case is explicitly excluded.
- **Exceptional-residue selection preserves the answer.** The proof follows the selected `(Q, s)` or `(2Q, s/2)` values and proves the same product for either Boolean branch. It does not need to prove that the selector identifies exactly the six exceptional residues to establish soundness. That stronger property matters for completeness and witness generation.
- **Incomplete affine formulas have supporting guards.** [`GroupLaw.lean`][group] requires distinct x-coordinates before chord division. [`Guards.lean`][guards] derives point-level separation from the canonical-limb or bounded-slope constraints. [`QuadAdd.lean`][quad] treats the last-step doubling case separately and rules out the second zero denominator using the slope equations and nonzero y-coordinate.
- **Fixed-base tables are connected to the generator.** [`Comb.lean`][comb] checks lengths, curve membership, the initial generator, doubling, odd multiples, negations, inter-window transitions, and the top correction. [`CombWindows.lean`][windows] connects the extracted table limbs to those certified points. The unguarded comb additions rely on the explicit scalar bounds in `chain_x_distinct`, rather than assuming arbitrary affine additions are safe.
- **The custom normalization tactic proposes rather than trusts a result.** [`ReflectTactic.lean:166`][reflect] uses unsafe evaluation to propose a normal form, but `kernelEq` constructs `decide +kernel` proofs for both sides before applying the soundness theorem. I did not treat that unsafe evaluator as an arbitrary-proof escape.

### Remaining P-256 assurance boundaries

**Lookup soundness is assumed, not proved for the production implementation.** [`LookupSound`][layout] assumes accepted range queries are below their bounds. [`RowLookupSound`][rows] assumes the returned row is exactly the row at an in-range index. In production, these are custom commitment/log-derivative arguments in [`emfield/rangecheck.go`][rangego] and [`emcurve/lookup.go`][rowgo]. Their extraction branches substitute opaque predicates; [`CodeExtractor.Defer`][defer] records callbacks without executing or translating their constraints. Thus a defect in those production arguments is outside what these conditional Lean results establish. Re-extracting and diffing the opaque calls cannot establish that missing implication. This is a documented trust boundary, not evidence that either lookup implementation is exploitable.

**The curve's order facts remain axioms.** [`Assumptions.lean`][assumptions] supplies primality of `p` and `n`, and `∀ Q, n • Q = 0`; [`FormalVerification/Lemmas.lean:7`][bnprime] supplies BN254 primality. The universal order axiom is used in scalar cancellation, reduction modulo `n`, and the exclusion of two-torsion. Generator membership and discriminant nonvanishing have concrete proof terms, but the order axiom is not a consequence proved by this project. The comment that every library axiom lives in `Assumptions.lean` also omits the imported BN254 axiom.

**These are soundness proofs, not completeness or witness-generator proofs.** They start with a satisfying extracted relation and do not construct one for every valid key/scalar. In particular, `completeAdd_sound` means soundness of the addition/doubling gadget; it is not a completeness theorem, and its documented behavior rejects inverse points. The rational-reconstruction hint and avoidance of exceptional intermediate states are not shown to produce satisfying witnesses for every supported input.

One concrete reason not to silently reverse the guard arguments: the native slope guard checks a product of `d(d² − p²)` factors modulo the BN254 scalar modulus `q`. At the abstract integer-guard level, `v = q + 1` and `h = 1` satisfy the magnitude bounds and `v ≠ ±h (mod p)`, but the native factor for `v − h` is zero. This shows the native guard is a sufficient condition for P-256 slope separation, not an equivalent one. I have not established that this pair occurs in a valid complete ECDH execution, and am not reporting a concrete rejected-key exploit.

## Findings

### 1. [P1] The default build and CI never check the P-256/encryption proof library

**Location:** [`lakefile.lean:19`][lake], [`Main.lean:1`][main], and [the CI build step][ci].

`VerifiableEncryption` is declared with submodule globs but is not a default target. The only `@[default_target]` is the executable rooted at `Main`, whose local import closure contains seven modules and zero `VerifiableEncryption` modules. CI invokes plain `lake build`, as does the `lean-build` recipe. The installed, pinned Lake source resolves a package's default build from `pkg.defaultTargets`, not from every declared library.

Consequently, the job labelled “checks all theorems” can succeed without elaborating `scalarMulChecked_sound`, `scalarMulBase_sound`, `agreeKey_sound`, or any of the encryption field certificates and bridges. Circuit regeneration checks source drift but does not check the proof library. A type error in a P-256 proof is outside the current build dependency graph.

**Fix:** make `VerifiableEncryption` a default target, or explicitly include it in both CI and the local verification recipe, e.g. `lake build formal-verification VerifiableEncryption`. Preserve the submodule glob so proof modules that are not imported by `Circuit.lean` are included. This recommended command was not executed.

### 2. [P1] The Merkle entry point introduces an inconsistent hash axiom

**Location:** [`Main.lean:18`][mainhash], with the actual definition in [`ProvenZk/Hash.lean:5`][hash].

`CollisionResistant h` means unrestricted injectivity: `h i1 = h i2 → i1 = i2`. Here `poseidon₂` maps a two-element vector over a finite field of size `q` into that same field. Its domain has `q²` elements and codomain has `q`, with `q > 1`. Injectivity is impossible by the pigeonhole principle.

Adding this proposition as a global axiom makes the environment importing `Main` inconsistent: it can derive `False`, and therefore arbitrary conclusions. The inclusion/non-inclusion and input-hash binding results depending on it are not meaningful unconditional guarantees for concrete Poseidon. Computational difficulty of finding a collision does not imply that collisions do not exist. The additional universal no-zero-preimage axiom is likewise stronger than a computational preimage-resistance claim, though the injectivity axiom alone already establishes the inconsistency.

**Fix:** prove reductions that return either the desired membership/binding result or a concrete collision (and, where relevant, a zero preimage). Alternatively, state a scoped collision-free condition over the specific finite set of nodes used in a proof. Do not globally assert injectivity of the concrete compressing hash. Keep the cryptographic hardness claim separate from the deterministic Lean statement.

**P-256 impact:** this axiom is outside the P-256 import closure; it does not invalidate those conditional theorem statements.

### 3. [P2] The AES block soundness theorem does not prove the extracted block circuit

**Location:** [`Aes/Ctr.lean:88`][ctr] versus [`Circuit/Top.lean:787`][aesraw].

`AesCtrBlock_sound` assumes arbitrary round keys, a supplied initial state, hand-written `AesRoundState` relations, and a supplied final-round relation. Its conclusion is about `circuitEncryptBlock rk blk`, not `encryptBlock key (counterBlock nonce 2)` or `ctrEncrypt key nonce plaintext`. It never takes `AesCtrBlock_32_12_16_16` as a premise.

There is useful lower-level work: the CPS lemmas in `Aes/Gadgets.lean` refer to extracted gadgets, and the untracked `keyExpansion_cps` refers to `AesKeyExpansion_32`. However, no theorem outside the generated circuit modules references `AesCtrBlock_32_12_16_16`, and `keyExpansion_cps` has no consumer. The nonce/counter initialization, cached first round, round wiring, key schedule, and final public ciphertext equalities have not been composed into the claimed block result. A wiring regression can leave the current abstract theorem unaffected.

**Fix:** add a theorem whose premise is the extracted block predicate, derive every intermediate invariant through the CPS lemmas, and conclude equality with the existing AES/CTR specification using the supplied key, nonce, and plaintext. Connect the arbitrary-round-key model to `Spec.encryptBlock` explicitly.

### 4. [P2] The extracted KDF and envelope have no semantic correctness theorem

**Location:** [`Circuit/Top.lean:948`][kdfraw] and [`Circuit/Top.lean:1375`][envraw].

`KeySchedule_32_12` and `Envelope_32_65_16_16` are constraint definitions. Neither is referenced by a semantic theorem elsewhere in the Lean source. `FieldBytesBE_32`, which connects field values to the truncated key and nonce bytes, also lacks a separate correctness result. The older `FormalVerification.poseidon₂` proofs do not by themselves establish the semantics of the separate `ZolanaVE` KDF and its three- and seven-input hash uses.

Static comparison of the visible wiring finds the expected domain values, key-high/key-low byte slices, and nonce suffix from `poseidon_kdf.go`. That source comparison does not turn the generated definitions into a proof that the packed P-256 shared secret produces the intended key, nonce, and ciphertext. Regenerating matching definitions after a KDF wiring change provides no semantic specification to reject the change.

**Fix:** prove canonical field-byte decomposition, specify and prove the KDF's domain/order/truncation behavior, then compose the P-256, KDF, and AES results into a theorem over the extracted envelope predicate. Cryptographic confidentiality is a separate claim from functional correctness.

### 5. [P2] The extracted envelope omits the production merge context and most of its plaintext

**Location:** [`circuits/formal/ve/circuits.go:124`][envwrapper], [`Circuit/Top.lean:1354`][envhash], and [`circuits/spp_merge/default.go:84`][merge].

The formal wrapper encrypts a 16-byte plaintext and never supplies `Envelope.Context`. Its generated shared-secret hash is therefore `Poseidon_7`. Production merge supplies `Context: c.Nullifiers[0]`; `Envelope.Encrypt` appends that context, producing an eight-input preimage. Production also encrypts 40 bytes: 8 amount bytes plus 31 and 1 mint bytes, as defined in [`spp_merge/shared/derivation.go`][derivation].

Thus even a completed theorem about the current extracted envelope would cover a different circuit specialization. It would not cover the nullifier-bound shared secret, counters after the first block, or the partial final block used by merge. The extraction drift check cannot detect a regression confined to the context branch because that branch is never taken by this wrapper.

**Fix:** extract and prove a specialization matching the production context and 40-byte payload, or prove a genuinely parameterized envelope/CTR result and instantiate it for production. Reuse production domain constants in the wrapper to prevent an additional independent source of drift.

## Other circuit ties and limits

The Merkle/full-field proofs refer to the extracted predicates. In particular, `AssertStrictlyOrdered_mirror` and `AssertStrictlyOrdered_rw` connect the generated ordering gadget to strict comparison of canonical field values. The formal wrappers call the same `MerkleRootGadget`, `IndexedLeafHash`, and ordering implementation used by transaction and merge. Their depth/batch specialization is 32/40/8.

Those standalone wrapper theorems do not prove production conditional inclusion for dummy inputs, ownership, balance conservation, nullifier derivation, or the complete public-input hash. Production uses additional guards and `HashChain4`/`RightHashChain4` compositions, whereas the formal wrapper uses its own two-column `HashChain` statement. The source connection supports shared-gadget coverage only.

No claim is made here that the checked-in generated constraints are byte-for-byte fresh, that any theorem elaborates successfully, or that a deployed verifying key corresponds to these sources. Establishing those would require work deliberately excluded by the request. The findings above follow from the inspected definitions, theorem signatures, import graph, and production call sites.

[scalar]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/ScalarMul.lean:29
[base]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/ScalarMulBase.lean:19
[agree]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/AgreeKey.lean:15
[derive]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/DerivePublicKey.lean:13
[instances]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Field/Instances_1.lean:14
[plain]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Field/PlainCheck.lean:318
[wrappers]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/formal/ve/circuits.go:54
[gadgets]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/verifiable-encryption/p256/emcurve/gadgets.go:95
[den]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/ScalarMul.lean:192
[chain]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/Ladder.lean:201
[group]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/GroupLaw.lean:31
[guards]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/Guards.lean:39
[quad]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/QuadAdd.lean:31
[comb]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/Comb.lean:75
[windows]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/CombWindows.lean:23
[reflect]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Field/ReflectTactic.lean:166
[layout]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Field/Layout.lean:127
[rows]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/LadderTable.lean:13
[rangego]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/verifiable-encryption/p256/emcurve/emfield/rangecheck.go:64
[rowgo]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/verifiable-encryption/p256/emcurve/lookup.go:49
[defer]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/tools/gnark-lean-extractor/extractor/extractor.go:330
[assumptions]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Assumptions.lean:24
[bnprime]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/FormalVerification/Lemmas.lean:7
[lake]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/lakefile.lean:19
[main]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/Main.lean:1
[ci]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/.github/workflows/formal-verification.yml:65
[mainhash]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/Main.lean:18
[hash]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/.lake/packages/proven-zk/ProvenZk/Hash.lean:5
[ctr]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Aes/Ctr.lean:88
[aesraw]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Top.lean:787
[kdfraw]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Top.lean:948
[envraw]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Top.lean:1375
[envwrapper]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/formal/ve/circuits.go:124
[envhash]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Top.lean:1354
[merge]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/spp_merge/default.go:84
[derivation]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/spp_merge/shared/derivation.go:25
