# Review: `formal-verification` Lean code, P-256 focus

**Scope.** Static review (no build executed) of
`prover/server/formal-verification/VerifiableEncryption/`, with the P-256
formalization (`Assumptions.lean`, `Curve/`, `CombTables.lean`,
`EmcurveChecks.lean`, the `scalarMulBase` / `scalarMulChecked` /
`DerivePublicKey` / `AgreeKey` soundness theorems) as the focus. Generated
tables and certificate constants were additionally re-checked with
independent Python EC arithmetic (not by running Lean). The Go circuit
(`circuits/verifiable-encryption/p256/emcurve/`) and the extractor
(`tools/gnark-lean-extractor/`) were read for semantic comparison.

## Verdict

**No correctness bug found in the P-256 Lean code.** Every hand-written
statement and every generated constant I checked is consistent, and most
load-bearing facts are kernel-verified (`decide +kernel` / `rfl`), so a
wrong constant there would fail compilation rather than silently misprove.
Details below; the residual risk is confined to the explicitly declared
trusted base (§3).

## 1. What was independently verified

### P-256 parameters and generator
- `Assumptions.lean` / `Curve/P256.lean`: `p`, `n`, `b`, `a = -3`, `Gx`,
  `Gy` match the NIST P-256 (secp256r1) specification exactly.
  `Field/Canonical.lean`'s duplicated `p256P` / `p256N` agree with them.
- The three axioms (`p256_prime`, `p256_order_prime`, `p256_point_order`)
  are true for P-256 (cofactor 1) and are the documented, weakest forms
  the proofs consume.
- The discriminant argument (`Δ_ne_zero`) and the no-2-torsion derivation
  from `n` odd are correct.

### Comb tables (`CombTables.lean`, generated)
All 52 windows × 32 entries, the 51 `steps` points and both `topEven`
points were re-computed with independent Python EC arithmetic:
- `windows[t][j] = (2j + 1 - 2^w)·2^(5t)·G` for **every** entry
  (w = 5 for t < 51, w = 1 for t = 51). All points on curve, all
  negation pairs present.
- `steps[t] = 2^(5t+1)·G` (a ×32 chain starting at `2·G`).
- `topEven[j] = windows[51][j] + (−G)`.

These are exactly the relations the certificate (`combCert`: `cBase`,
`cDouble`, `cOdd`, `cNeg`, `cNext`, `cTop`) asserts, and
`combCert_true := by decide +kernel` kernel-checks them.

### Fixed-base comb logic
- `recode_identity`: signed-odd-digit sum
  `Σ(2r_t − 31)·2^(5t) + (2·top − 1)·2^255 − (1 − π) = 2r + π − 2^256` —
  verified algebraically.
- Recoding constraint `2·RC + π ≡ S + 2^256 (mod n)` (via
  `cert_hcd1dd84c`, exprValue `2·RC + π − S − twoPow`) together with
  `comb_result`/`comb_final` yields exactly `S·G`; the parity fold
  (`topScalar`, `topEntry`, selector `bit256 + 2·π`) was case-checked
  against the tables for all four (bit256, π) combinations.
- `chain_x_distinct`: the distinct-x guard argument is tight and correct:
  `|partial| ≤ 2^(5t) − 1 < 2^(5t) ≤ |d·2^(5t)| ≤ 31·2^(5t)` and
  `|a ± d·2^(5t)| < 32·2^(5t) ≤ 2^255 < n` for t ≤ 50.
- Bit layout: 257 bits (`197 + 60`), windows t = 0..50 read bits
  `1+5t .. 5+5t`, top bit is bit 256, parity bit is bit 0 — consistent
  throughout (`ScalarMulBase.lean`, `CombBase.lean`).

### Variable-base ladder vs Go `ladder.go`
- Slot table order, the `15 − idx` mirroring, and the **y-negation on
  even rows** in `rowPoint` match `packedTableLookup` exactly.
- Selector layout `idx = n_i + 2·d_i + 4·n_{i−1} + 8·d_{i−1}` matches
  Go; `digQ`/`digR` are the correct signed base-4 digits `2v − 3`
  (spot-verified for several `idx`, plus the Lean proof covers all 16).
- `ladder_scalar_identity` (64 quadruple steps from `acc = Q + R`, low-bit
  corrections `b₀ − 1`, 129-bit range) verified algebraically.
- The six exceptional-residue guards (`x(R)≠x(Q)`, `x(R)≠x(3Q)`,
  `x(3R)≠x(Q)` ⇔ s ∉ {±1, ±3, ±1/3}) match Go step 2, and
  `slots_nonzero`/`rows_nonzero` correctly derive all eight slot
  nonzero facts from them.
- `ladder_chain` (the binding argument `num·Q + den·R = 0`,
  `s·(ε·den) + num ≡ 0 (mod n)`, `1 ≤ den < n` ⇒ `Prod = s·Q`) is sound;
  `inv2Limbs = (n+1)/2` is `rfl`-verified.

### Group law (`Curve/GroupLaw.lean`, `Guards.lean`)
- `chord_add` / `tangent_double` / `triple` / `complete_add` match the
  Weierstrass `a = −3` formulas; the cross-multiplied certificate
  relations (`chordRel`, `doubleRel`, `negRel`) are linear in the result
  coordinates and were re-derived by hand.
- `halfQuartic X Y l = l⁴ − 6Xl² − 8Yl − 3X² + 12` is the correct
  point-halving quartic (constant term `−4a = +12`); the identity
  `halfQuartic = 4·(2·y_H·l − (3x_H² − 3))` under the doubling
  substitutions was re-derived and holds.
- `slopeFactor` / `distinctSlope_guard` (`|v|,|h| < p`, product nonzero
  natively ⇒ `v ≢ ±h (mod p)`) is correct.

### Theorem statements vs Go semantics
- `derivePublicKey_sound`: `mkPoint hE = (bytesBE sk)•G`, `¬ n ∣ sk`,
  compressed packing `lo = (2 + y%2)·2^240 + x/2^16`, `hi = x % 2^16` —
  matches the Go `KeyAgreement` packing comment (exclusive `key[0..31]`
  reading, the only one that fits a field element).
- `agreeKey_sound`: 65-byte uncompressed input with `pk[0] = 4`, on-curve
  and `< p` bounds on both coordinates, `S = sk·Q`, `E = sk·G`, shared-x
  packing `(x/2^8, x%2^8)` — matches Go field order
  (recipient, ephemeral, shared).
- `scalarMulChecked_sound` / `scalarMulBase_sound`: conclusions state the
  correct group equalities with canonical bounds.

### Extractor variadic-add defect — confirmed fixed
Commit `a5567e14e` recorded that variadic `api.Add` was extracted as
self-referential (`∃ g, g = g + x`, forcing `x = 0`), making the
denominator-nonzero check and table selectors unfaithful. The current
extractor (`lean_export.go:genOpCall`) folds `OpAdd/OpSub/OpMul` with
> 2 operands left into one nested expression under a single binder, with
a comment documenting exactly this. A scan of all extracted Lean files
finds **zero** self-referential gate equations. The Go denominator check
(`api.Add(denominatorBits[0], denominatorBits[1], denominatorBits[2:]...)`
≠ 0) is now faithfully modeled.

## 2. AES spot check (agent's new untracked files)

`Aes/Spec.lean`'s S-box is the standard FIPS-197 table and is proven
equal to the mathematical `affine(ginv x)` spec; `rcon`, `rotWord`, and
the AES-256 key schedule match FIPS-197 §5.2; `KeySpec.lean`'s recurrences
are consistent with that spec. No issues found.

## 3. Trusted base (declared, unverified-by-design)

These are the only statements a future change could silently weaken —
they are all correctly stated today:

- `Assumptions.lean`: `p256_prime`, `p256_order_prime`,
  `p256_point_order` (axioms; upgrade paths documented).
- `Field/Layout.lean`: `LookupSound RangeCheck 11` — idealised soundness
  of the log-derivative range table for widths 2..11.
- `Curve/LadderTable.lean`: `RowLookupSound` — idealised 16-row packed
  table lookup. Note it asserts the returned row is at the index but
  says nothing about the table's provenance; that link is
  `TableOK … (Ladder.rowPoint i Q R)`, supplied by the caller.

## 4. Minor observations (not bugs)

1. `agreeKey_sound` does not surface `¬ n ∣ sk` the way
   `derivePublicKey_sound` does. Soundness is unaffected (the existential
   only claims anything when the circuit is satisfied, and `sk ≡ 0` is
   unrepresentable in affine coordinates), but the guard is an
   asymmetric API surface worth a comment.
2. `complete_add` (and the Go circuit) is unsatisfiable on `P + (−P)` —
   a documented completeness limitation ("rejecting inverse points"),
   correctly mirrored by the Lean statement.
3. `agreeKey_sound` states no `yS < p` bound (only `xS` is packed);
   harmless but slightly asymmetric with `xS < p`.
4. `Comb.width t = if t < 51 then 32 else 2` returns 2 for `t ≥ 52`;
   only used below 52 (pinned by `cLen`), so harmless.
5. Heavy reliance on `decide +kernel` over 256-bit `Nat` arithmetic is
   sound but couples proof-check time to GMP kernel evaluation; the
   primality axioms remain the main unverifiable-by-`decide` gap (the
   file already notes the Pratt-certificate upgrade path).

## 5. Residual risks outside the Lean code

- **Extraction fidelity**: the soundness theorems are proved against the
  extracted relations in `Circuit/*.lean`; fidelity of the extractor
  itself (and of the name-hash disambiguation `_h<hash>`) to the Go
  circuit is outside the Lean trusted base and was only spot-checked
  (packing, ladder, comb, variadic ops). A regeneration drift would not
  be caught by Lean.
- No top-level `Envelope` soundness theorem exists yet; the composition
  (KDF input wiring, AES-CTR counter handling) is unreviewed at the
  theorem level.
