import VerifiableEncryption.Curve.AgreeKeyAux
import VerifiableEncryption.Curve.Native

/-!
Constructive components for P-256 completeness.

These are witness constructors for actual extracted predicates, not converses
obtained by assuming those predicates. They do not yet constitute a completeness
theorem for ScalarMulChecked, ScalarMulBase, or AgreeKey. In particular the
native distinct-slope premise below has not been derived for ladder prefixes.
-/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

/-- Completeness of the production range table, separately from lookup soundness.
The bound concerns the integer being cast, so no native-field wrap is permitted. -/
def RangeComplete : Prop :=
  ∀ (bits value : ℕ), 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F)

/-- Mathematical input domain of production key agreement. Scalars are 32-byte
integers with nonzero residue, not necessarily less than the group order.
There are no ladder guards or successful-hint premises in this domain. -/
def ValidAgreementInput (sk : List.Vector F 32) (pk : List.Vector F 65) : Prop :=
  (∀ i, (sk.get i).val < 256) ∧
  (∀ i, (pk.get i).val < 256) ∧
  pk.get 0 = 4 ∧
  bytesBE pk 1 32 < p ∧ bytesBE pk 33 32 < p ∧
  OnCurve ((bytesBE pk 1 32 : ℕ) : Fp) ((bytesBE pk 33 32 : ℕ) : Fp) ∧
  bytesBE sk 0 32 % n ≠ 0

/-- Fixed-base derivation accepts the same nonzero-residue scalar domain. -/
def ValidSecretInput (sk : List.Vector F 32) : Prop :=
  (∀ i, (sk.get i).val < 256) ∧ bytesBE sk 0 32 % n ≠ 0

/-- The witness returned to the continuation by a low-bit split. -/
def splitWitness (value width : ℕ) : List.Vector F 2 :=
  ((value / 2 ^ width : ℕ) : F) ::ᵥ ((value % 2 ^ width : ℕ) : F) ::ᵥ List.Vector.nil

/-- Production 11-bit range pieces for an integer of at most 31 bits. -/
def pieces3 (value : ℕ) : List.Vector F 3 :=
  ((value % 2048 : ℕ) : F) ::ᵥ ((value / 2048 % 2048 : ℕ) : F) ::ᵥ
    ((value / 4194304 : ℕ) : F) ::ᵥ List.Vector.nil

def pieces2 (value : ℕ) : List.Vector F 2 :=
  ((value % 2048 : ℕ) : F) ::ᵥ ((value / 2048 : ℕ) : F) ::ᵥ List.Vector.nil

theorem pieces3_recompose (v : ℕ) :
    v = v % 2048 + v / 2048 % 2048 * 2048 + v / 4194304 * 4194304 := by
  omega

theorem pieces2_recompose (v : ℕ) : v = v % 2048 + v / 2048 * 2048 := by
  omega

theorem split_recompose (v w : ℕ) :
    (v : F) = ((v / 2 ^ w : ℕ) : F) * (2 ^ w : ℕ) + ((v % 2 ^ w : ℕ) : F) := by
  have he : v = v / 2 ^ w * 2 ^ w + v % 2 ^ w := by
    simpa [Nat.mul_comm] using (Nat.div_add_mod v (2 ^ w)).symm
  simpa only [Nat.cast_add, Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat] using
    congrArg (fun x : ℕ => (x : F)) he

theorem split_1_8_complete (hr : RangeComplete) (v : ℕ) (hv : v < 256)
    (k : List.Vector F 2 → Prop) (hk : k (splitWitness v 1)) :
    SplitLowBits_1_8_h2c1d332a (v : F) k := by
  unfold SplitLowBits_1_8_h2c1d332a
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.eq, exists_eq_left]
  refine ⟨splitWitness v 1, ?_, ?_, ?_, hk⟩
  · exact hr 7 (v / 2) (by norm_num) (by norm_num) (by omega)
  · change (1 - ((v % 2 : ℕ) : F)) * ((v % 2 : ℕ) : F) = 0
    have hb : v % 2 = 0 ∨ v % 2 = 1 := by omega
    rcases hb with hb | hb <;> simp [hb]
  · simpa [splitWitness] using split_recompose v 1

theorem split_1_32_complete (hr : RangeComplete) (v : ℕ) (hv : v < 2 ^ 32)
    (k : List.Vector F 2 → Prop) (hk : k (splitWitness v 1)) :
    SplitLowBits_1_32_h2c1d332a (v : F) k := by
  unfold SplitLowBits_1_32_h2c1d332a
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.eq, exists_eq_left]
  refine ⟨splitWitness v 1, pieces3 (v / 2), ?_, ?_, ?_, ?_, ?_, ?_, hk⟩
  · exact hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num))
  · exact hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num))
  · exact hr 9 _ (by norm_num) (by norm_num) (by norm_num at hv ⊢; omega)
  · simpa [splitWitness, pieces3] using
      congrArg (fun x : ℕ => (x : F)) (pieces3_recompose (v / 2))
  · change (1 - ((v % 2 : ℕ) : F)) * ((v % 2 : ℕ) : F) = 0
    have hb : v % 2 = 0 ∨ v % 2 = 1 := by omega
    rcases hb with hb | hb <;> simp [hb]
  · simpa [splitWitness] using split_recompose v 1

theorem split_8_32_complete (hr : RangeComplete) (v : ℕ) (hv : v < 2 ^ 32)
    (k : List.Vector F 2 → Prop) (hk : k (splitWitness v 8)) :
    SplitLowBits_8_32_h2c1d332a (v : F) k := by
  unfold SplitLowBits_8_32_h2c1d332a
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.eq, exists_eq_left]
  refine ⟨splitWitness v 8, pieces3 (v / 256), ?_, ?_, ?_, ?_, ?_, ?_, hk⟩
  · exact hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num))
  · exact hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num))
  · exact hr 2 _ (by norm_num) (by norm_num) (by norm_num at hv ⊢; omega)
  · simpa [splitWitness, pieces3] using
      congrArg (fun x : ℕ => (x : F)) (pieces3_recompose (v / 256))
  · exact hr 8 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num))
  · simpa [splitWitness] using split_recompose v 8

theorem split_16_32_complete (hr : RangeComplete) (v : ℕ) (hv : v < 2 ^ 32)
    (k : List.Vector F 2 → Prop) (hk : k (splitWitness v 16)) :
    SplitLowBits_16_32_h2c1d332a (v : F) k := by
  unfold SplitLowBits_16_32_h2c1d332a
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.eq, exists_eq_left]
  refine ⟨splitWitness v 16, pieces2 (v / 65536), ?_, ?_, ?_,
    pieces2 (v % 65536), ?_, ?_, ?_, ?_, hk⟩
  · exact hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num))
  · exact hr 5 _ (by norm_num) (by norm_num) (by norm_num at hv ⊢; omega)
  · simpa [splitWitness, pieces2] using
      congrArg (fun x : ℕ => (x : F)) (pieces2_recompose (v / 65536))
  · exact hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num))
  · exact hr 5 _ (by norm_num) (by norm_num) (by norm_num; omega)
  · simpa [splitWitness, pieces2] using
      congrArg (fun x : ℕ => (x : F)) (pieces2_recompose (v % 65536))
  · simpa [splitWitness] using split_recompose v 16

def compressedWitness (X Y : List.Vector F 8) : List.Vector F 2 :=
  (((2 + (Y.get 0).val % 2 : ℕ) : F) * K_0 +
    (((X.get 0).val / 65536 : ℕ) : F) + X.get 1 * 65536 + X.get 2 * 281474976710656 +
    X.get 3 * K_6275 + X.get 4 * K_1180 + X.get 5 * K_6276 +
    X.get 6 * K_6277 + X.get 7 * K_6278) ::ᵥ
    (((X.get 0).val % 65536 : ℕ) : F) ::ᵥ List.Vector.nil

/-- Every bounded pair of low coordinate limbs admits the extracted
compressed packing witness. Higher limbs are native inputs of this gadget;
their canonical-coordinate interpretation belongs to its callers. -/
theorem compressedPacking_complete (hr : RangeComplete) (X Y : List.Vector F 8)
    (hx : (X.get 0).val < 2 ^ 32) (hy : (Y.get 0).val < 2 ^ 32)
    (k : List.Vector F 2 → Prop) (hk : k (compressedWitness X Y)) :
    CompressedPacking_8_8_32_h2c1d332a X Y k := by
  unfold CompressedPacking_8_8_32_h2c1d332a
  rw [eq_natCast_val (Y.get 0)]
  apply split_1_32_complete hr _ hy
  rw [eq_natCast_val (X.get 0)]
  apply split_16_32_complete hr _ hx
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, exists_eq_left]
  refine (congrArg k ?_).mpr hk
  apply List.Vector.toList_injective
  norm_num [compressedWitness, splitWitness, List.Vector.get, List.Vector.head,
    Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod,
    K_0, K_6275, K_1180, K_6276, K_6277, K_6278]
  ring

/-- Exact native-field obligation in the extracted slope guard. A P-256
slope inequality alone is insufficient: integer factors may vanish modulo Order. -/
theorem distinctSlope_complete (Λ : ElemVal 8) (other : F)
    (hne : slopeFactor ((Λ.value : F) - other) *
      slopeFactor ((Λ.value : F) + other) ≠ 0) :
    AssertDistinctSlope_8_h16c15a53 Λ.limbs other := by
  unfold AssertDistinctSlope_8_h16c15a53
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, GatesDef.ne, exists_eq_left]
  refine ⟨?_, trivial⟩
  have hv : ((Λ.value : ℤ) : F) = 0 + Λ.limbs.get 0 * 1 +
      Λ.limbs.get 1 * 4294967296 + Λ.limbs.get 2 * K_390 +
      Λ.limbs.get 3 * K_391 + Λ.limbs.get 4 * K_392 +
      Λ.limbs.get 5 * K_393 + Λ.limbs.get 6 * K_394 + Λ.limbs.get 7 * K_395 := by
    rw [value_cast]; ring
  rw [← hv, K_1176_eq]
  exact hne

/-- Assemble the actual distinct-x predicate from its two canonical checks
and the native sum guard. This preserves the eager canonical checks on both
inputs; it does not replace them by equality of emulated-field residues. -/
theorem distinctX_complete (X Y : List.Vector F 8)
    (hx : AssertCanonical_8_0_hc36017e9 X)
    (hy : AssertCanonical_8_0_hc36017e9 Y)
    (hne : ∑ i : Fin 8, (X.get i - Y.get i) ^ 2 ≠ 0) :
    AssertDistinctX_8_8_h83dcf683 X Y := by
  unfold AssertCanonical_8_0_hc36017e9 at hx hy
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, GatesDef.eq, exists_eq_left] at hx hy
  obtain ⟨p2, pz2, p6, p5, p17, pz17, p20, pz20, pfin, -⟩ := hx
  obtain ⟨q2, qz2, q6, q5, q17, qz17, q20, qz20, qfin, -⟩ := hy
  unfold AssertDistinctX_8_8_h83dcf683
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, GatesDef.eq, GatesDef.ne, exists_eq_left]
  refine ⟨p2, pz2, p6, p5, p17, pz17, p20, pz20, pfin,
    q2, qz2, q6, q5, q17, qz17, q20, qz20, qfin, ?_, trivial⟩
  simpa only [Fin.sum_univ_eight, pow_two, zero_add] using hne

/-- Concrete failure of the proposed converse "different P-256 slopes
imply a satisfiable native slope guard": Order and zero are different in
Fp, but the native factor is zero. This is an algebraic guard counterexample,
not a claimed production key-agreement input counterexample. -/
theorem nativeSlope_alias :
    ((Order : ℕ) : Fp) ≠ 0 ∧
    slopeFactor (((Order : ℕ) : F) - 0) *
      slopeFactor (((Order : ℕ) : F) + 0) = 0 := by
  constructor
  · intro he
    have hv := congrArg ZMod.val he
    rw [ZMod.val_cast_of_lt (by norm_num [Order, p]), ZMod.val_zero] at hv
    norm_num [Order] at hv
  · simp [slopeFactor, ZMod.natCast_self]

/-- Mathematical doubling witnesses exist for every affine input. This
constructs the denominator inverse and coordinates, but is deliberately
separate from the extracted CheckPolynomial/carry constructors. -/
theorem affineDouble_exists {x y : Fp} (hP : OnCurve x y) :
    ∃ l xd yd : Fp, 2 * l * y = 3 * x ^ 2 - 3 ∧
      xd = l ^ 2 - 2 * x ∧ yd = l * (x - xd) - y ∧
      ∃ hD : OnCurve xd yd, 2 • mkPoint hP = mkPoint hD := by
  let l := (3 * x ^ 2 - 3) / (2 * y)
  have hd : 2 * y ≠ 0 := mul_ne_zero two_ne_zero_Fp (y_ne_zero_of_onCurve hP)
  have hl : 2 * l * y = 3 * x ^ 2 - 3 := by
    calc
      2 * l * y = l * (2 * y) := by ring
      _ = 3 * x ^ 2 - 3 := div_mul_cancel₀ _ hd
  exact ⟨l, l ^ 2 - 2 * x, l * (x - (l ^ 2 - 2 * x)) - y,
    hl, rfl, rfl, tangent_double hP hl rfl rfl⟩

/-- Mathematical incomplete-addition witnesses, with the actual necessary
distinct-x obligation exposed. It is not imposed on valid API inputs. -/
theorem affineAdd_exists {xp yp xq yq : Fp}
    (hP : OnCurve xp yp) (hQ : OnCurve xq yq) (hx : xp ≠ xq) :
    ∃ l xs ys : Fp, l * (xq - xp) = yq - yp ∧
      xs = l ^ 2 - xp - xq ∧ ys = l * (xp - xs) - yp ∧
      ∃ hS : OnCurve xs ys, mkPoint hP + mkPoint hQ = mkPoint hS := by
  let l := (yq - yp) / (xq - xp)
  have hl : l * (xq - xp) = yq - yp :=
    div_mul_cancel₀ _ (sub_ne_zero.mpr hx.symm)
  exact ⟨l, l ^ 2 - xp - xq, l * (xp - (l ^ 2 - xp - xq)) - yp,
    hl, rfl, rfl, slope_add hP hQ hx hl rfl rfl⟩

end ZolanaVE.P256.Completeness
