# Expanded static circuit review

**2026-10-10 update:** a [recheck of the newer source](/Users/jorrit/dev/worktrees/zolana2/ozone-osprey/zolana2/lean-circuit-recheck.md) found that the reported inverse-four guard mechanism has been removed and the one-block AES linkage theorem has been added. This report below records the earlier revision; consult the recheck for current status.

Reviewed worktree: `/Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514`, at HEAD `52a71cb723ebeb266d34e82867050192e8126240`, including the untracked AES `Block`, `KeyExpansion`, `KeySpec`, and `KeySteps` modules. Date: 2026-10-09.

Three GPT-6.1 Sol subagents independently reviewed P-256, emulated field arithmetic, and AES/KDF/envelope. The primary reviewer covered Merkle/full-field ordering and checked the reported findings. Proof infrastructure, CI, build configuration, and custom tactic internals were excluded. No tests, builds, Lean execution, circuit execution, generators, or numerical experiments were run. Findings below are source analysis, not solver reproductions or confirmation that the Lean files elaborate.

**New result:** a concrete P-256 completeness defect was found: the valid scalar `4⁻¹ mod n` cannot satisfy the variable-base ladder. The curve reviewer, field reviewer, and primary reviewer independently checked the algebra. No new defect permitting an incorrect accepted P-256 result was identified.

## 1. [P2, new] A valid inverse-four scalar is rejected by the P-256 ladder

**Location:** [ladder.go:136][ladder], and the corresponding unconditional assertion in [Circuit/Curve.lean:4914][rawguard].

The first low-bit correction constructs an incomplete addition before selecting which result to use:

```go
acc = c.selectPoint(numeratorBits[0], acc,
    c.guardedAddReducing(negatedInput, acc, true, false))
```

Go evaluates `guardedAddReducing` even when the bit is 1 and the circuit selects the unchanged accumulator. Its distinct-x assertion is consequently unconditional. The extracted Lean predicate preserves that assertion; this is not an extraction discrepancy.

### Concrete valid input

Use recipient `Q = G`, encoded as `0x04 || BE32(Gx) || BE32(Gy)`, and the scalar

```text
s = 4⁻¹ mod n = (3n + 1) / 4
sk = BE32(s)
```

Here `n` is the concrete P-256 group order in [Assumptions.lean][assumptions]. It ends in hexadecimal `51`, so `n ≡ 1 mod 4`. Therefore `s` is an integer with `0 < s < n`, has a valid 32-byte encoding, and its correct product is a nonidentity point. The argument also applies to any nonidentity P-256 recipient.

### Why every allowed decomposition fails

1. **The existing exception workaround does not select this input.** [ladder.go:41][exceptions] recognizes only `±1`, `±3`, and `±1/3`. Equality of `1/4` with any of these would make the large prime `n` divide a nonzero integer of magnitude at most 13. The scalar comparison sums cannot wrap: eight squared differences of 32-bit limbs sum to less than `2^67`, below the native field modulus. Thus the ladder receives the original `Q` and `s`.

2. **The denominator must be four times the numerator.** The decomposition constraints at [ladder.go:72][decomposition] give

   ```text
   0 ≤ u < 2^129,   0 < d < 2^129,   ε ∈ {−1, 1}
   s·ε·d + u ≡ 0 (mod n).
   ```

   Multiplying by 4 yields `4u + εd ≡ 0 (mod n)`. Its absolute magnitude is below `5·2^129 < n`, so it must be exactly zero over the integers. Hence `ε = −1`, `u > 0`, and `d = 4u`. In particular, the denominator's low bit is zero. This covers every permitted decomposition, not just the one the Go hint normally chooses.

3. **The signed product is a negative quarter of Q.** Assume a satisfying witness. The existing scalar-binding argument in [Ladder.lean:201][binding] and [ScalarMul.lean:932][scalarend] gives `Prod = sQ`. Therefore the signed point is `R = εProd = −sQ`, and `4R = −Q`.

4. **The final corrections force a forbidden accumulator.** Let `A` be the accumulator before the two low-bit corrections, and `C1`, `C2` the points afterward. Since the denominator bit is zero, the second correction gives `C2 = C1 − R`. The final equality requires `C2 = 3R`, so `C1 = 4R = −Q`. These correction equations are explicit in [LadderEnd.lean:65][closing] and the corresponding branches in [ScalarMul.lean:848][branches].

   - If `u` is **odd**, the first selector chooses `C1 = A`, so `A = −Q`. The eagerly constructed addition has operands `−Q` and `A = −Q`; its distinct-x guard rejects, even though that addition's result is discarded.
   - If `u` is **even**, the first correction gives `C1 = A − Q`, so `A = 0`, the group identity. A successful ladder accumulator is an affine on-curve point and therefore cannot be the identity; see [QuadAdd.lean:31][quad] and [P256.lean:79][finite]. This case cannot produce a satisfying intermediate witness either.

The longer recoding calculation agrees: before the corrections,

```text
A = (u + 1 − lowbit(u))Q + (d + 4 − lowbit(d))R
  = −lowbit(u)Q.
```

**Impact:** valid ECDH/key-agreement input is rejected. This is a completeness defect, not an incorrect shared-secret acceptance or a contradiction in the existing one-direction soundness theorem. The fixed-base public-key derivation is not shown defective by this example. No loss-of-funds or exploitable denial of service against another party is claimed.

**Fix direction:** ensure unselected correction branches remain satisfiable, for example by selecting safe operands before invoking an incomplete addition, and handle the doubling/identity cases required by selected branches. Simply removing the guard would remove a soundness precondition. Extending the exceptional-residue workaround needs its own analysis; adding a case is not a proof that all other valid scalars work. The exact input above is a useful regression case when execution is permitted.

## 2. [P1, previously identified] The Merkle hash assumption is mathematically inconsistent

**Location:** [Main.lean:18][mainhash] and [ProvenZk/Hash.lean:5][hash].

`CollisionResistant` is defined as unrestricted injectivity. The concrete two-input Poseidon maps `q²` field-element pairs into `q` field elements. For `q > 1`, this cannot be injective. Asserting it globally makes the environment importing `Main` inconsistent and permits arbitrary conclusions.

This remains a substantive mathematical issue within the circuit review scope, independent of proof infrastructure. The P-256 modules do not import `Main`, so this does not contaminate their proof chain. The appropriate statement is a reduction to a collision or a scoped collision-free condition on the values involved, rather than universal injectivity of concrete Poseidon. The no-zero-preimage assumption is also an explicit stronger-than-computational condition, but injectivity alone already establishes the inconsistency.

## 3–5. Remaining encryption proof coverage findings

These are gaps in formal coverage, not demonstrated AES/KDF circuit bugs. The new AES source files were included in this pass.

| Finding | Evidence and consequence | Required connection |
| --- | --- | --- |
| **3. [P2] Complete AES block linkage is unfinished.** | [Ctr.lean:88][ctr] proves a result from hand-written initial/round/final predicates and supplied round keys. New `KeyExpansion.lean` directly connects the extracted key expansion to all 240 specified bytes; new `Block.lean` supplies useful round, cache, and decode lemmas. At the inspected version, `Block.lean` ends after `packDecode_cps`, without a theorem consuming [the extracted block predicate][aesraw]. | Compose the key expansion, nonce/counter initialization, cached first round, subsequent rounds, and public-output equalities into a theorem over `AesCtrBlock_32_12_16_16`. |
| **4. [P2] KDF and envelope predicates lack semantic correctness theorems.** | [KeySchedule_32_12][kdfraw] and [Envelope_32_65_16_16][envraw] are generated constraint definitions. No theorem outside the generated definitions consumes them to establish the intended key, nonce, and encrypted payload. | Prove canonical field-byte decomposition, KDF domains/input order/truncation, and composition of the agreement, KDF, and AES results. |
| **5. [P2] The formal envelope specializes a different production path.** | [The formal wrapper][wrapper] encrypts 16 bytes with no context; [the generated shared-secret hash][envhash] is `Poseidon_7`. [Production merge][merge] supplies `Context = Nullifiers[0]` and encrypts 40 bytes. That exercises `Poseidon_8`, counters 2, 3, 4, and an eight-byte tail. | Extract/prove the production specialization, or establish a parameterized envelope/CTR result and instantiate it for the actual context and payload. |

## Arguments inspected without an additional located defect

### P-256 and emulated arithmetic

- The major curve theorems take actual extracted predicates and conclude equality with Mathlib's concrete P-256 group operations. The multiplication result is constrained; its hint is not assumed correct. Scalar bytes are checked before limb composition, and reduction modulo `n` is consistent with the APIs' stated behavior.
- The ladder binds a nonzero 129-bit denominator below `n`; cancellation uses the prime-order group facts. Either Boolean exceptional-scalar branch preserves the desired product, which explains why its exact exceptional-set classification is not needed for soundness. It is insufficient for completeness, as finding 1 demonstrates.
- Affine addition guards, last-step doubling equations, and fixed-base digit bounds support the divisions and incomplete additions used in the inspected arguments. Comb tables are connected to the concrete generator and to their extracted limbs.
- Integer carry lifting requires differences strictly below the native modulus. The no-top-coefficient path combines prefix divisibility, the native equation, and a global residual bound; the top coefficient is not simply ignored. Signed/lazy intervals and whole-value bounds are retained in the field contracts.
- Representative generated arithmetic bridges explicitly start from extracted checks and derive their semantic mirrors. `Reduced`/`Bounded` constructors are metadata-only, but inspected production boundaries establish the needed byte, limb, or lookup-derived bounds before using them.

### AES, KDF, and envelope wiring

- The key-expansion recurrence matches the specified word offsets, rotation/S-box cases, and seven round constants. The new proof derives initial key-byte bounds from lookups rather than assuming that truncation made the inputs valid bytes.
- The CTR cache dependency is correct in the inspected source: only first-round column 0 depends on counter byte 15; the remaining cached contributions depend on the high counter bytes. The tail uses the corresponding prefix of the final keystream. The block-count guard bounds the counter before conversion to `uint32`.
- Middle AES columns have at most five spread contributions, so base-6 digits do not carry. Chunk recomposition remains below `6^32`, itself below the native modulus. The table orientation and row-to-column rotations match the Lean specification.
- KDF domains, key-high-low128 followed by key-low-low128, and the nonce's low 96 bits match the generated wiring. Pinned gnark source retains the canonical modulus check when decomposing into 32 bytes and pads the top two bits with zero.
- Production envelope packing stays within 31 bytes per field element and includes the four packed envelope elements in the public-input hash. This inspection does not establish a full encryption confidentiality proof.

### Merkle and full-field comparison

- The Go Merkle loop consumes least-significant index bits and leaf-up siblings. The Lean bridge reverses both vectors for the library's root-down representation. Parent selection uses Boolean directions and the same left/right ordering.
- The 254-bit decomposition is canonical in the pinned gnark implementation. Splitting at 127 bits bounds the offset comparator below `2^128`, preventing native-field wraparound; the lexicographic high/low combination implements strict comparison.
- The non-inclusion predicate proves membership inside a stored open range. `RangeVector` supplies range validity/disjointness; initialization, insertion, and preservation of the global indexed-tree invariant are not established by these query theorems.
- Formal wrappers share the production Merkle/ordering gadgets, but their batch-8 two-column input hash is not a theorem about the whole production transaction/merge circuit, its padding logic, or its `HashChain4` compositions.

## Explicit limits and remaining scope

The curve results depend on primality of the native field, P-256 base field and group order, plus `nQ = 0` for every P-256 point. Range and row lookup soundness remain explicit assumptions. Static inspection found commitment of relevant queries/rows/results/counts before the challenge and degree-separation/cardinality guards in the concrete lookup implementations; this is not a formal proof of their cryptographic soundness or of gnark's commitment backend.

Production `SelfAgreeKey` computes `[s²]G` using the fixed-base comb and is mathematically consistent with self ECDH, but no extracted top-level predicate or theorem for that composition was found. ECDSA, the bit-based layout, complete custom-ring policies, and exhaustive classification of valid-input rejection cases were not reviewed in full.

The AES files were under concurrent development and untracked throughout this pass. Conclusions describe the source read, not future edits. Giant generated modules were inspected at critical boundaries and representative instances, not exhaustively regenerated or compared. Proof-infrastructure findings from the earlier report were not part of this review.

[ladder]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/verifiable-encryption/p256/emcurve/ladder.go:136
[rawguard]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Curve.lean:4914
[assumptions]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Assumptions.lean:13
[exceptions]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/verifiable-encryption/p256/emcurve/ladder.go:41
[decomposition]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/verifiable-encryption/p256/emcurve/ladder.go:72
[binding]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/Ladder.lean:201
[scalarend]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/ScalarMul.lean:932
[closing]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/LadderEnd.lean:65
[branches]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/ScalarMul.lean:848
[quad]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/QuadAdd.lean:31
[finite]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Curve/P256.lean:79
[mainhash]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/Main.lean:18
[hash]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/.lake/packages/proven-zk/ProvenZk/Hash.lean:5
[ctr]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Aes/Ctr.lean:88
[aesraw]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Top.lean:787
[kdfraw]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Top.lean:948
[envraw]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Top.lean:1375
[wrapper]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/formal/ve/circuits.go:124
[envhash]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/formal-verification/VerifiableEncryption/Circuit/Top.lean:1354
[merge]: /Users/jorrit/dev/zolana2/.claude/worktrees/agent-a147a003776d31514/prover/server/circuits/spp_merge/default.go:84
