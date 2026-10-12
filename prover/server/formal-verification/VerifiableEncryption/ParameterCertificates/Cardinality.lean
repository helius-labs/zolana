import Mathlib

/-!
Elementary finite-curve cardinality argument, independent of P-256's existing
point-order assumption. A short Weierstrass curve has at most two affine
points over each x-coordinate. If a certified nonidentity point is killed by
a prime n, the point group has cardinality divisible by n. A separate
no-two-torsion certificate makes that cardinality odd. Below 3n the only
positive odd multiple is n. No Hasse bound or curve-order axiom is used.
-/

namespace ZolanaVE.ParameterCertificates

open WeierstrassCurve.Affine
open scoped BigOperators Polynomial
open Classical

section PointCounting

variable {K : Type*} [Field K] [Fintype K]
    (W : WeierstrassCurve K)

def pointCoordinates : W.toAffine.Point → Option (K × K)
  | .zero => none
  | @Point.some _ _ _ x y _ => some (x, y)

theorem pointCoordinates_injective : Function.Injective (pointCoordinates W) := by
  intro A B h
  cases A with
  | zero =>
    cases B with
    | zero => rfl
    | some hb => cases h
  | @some xa ya ha =>
    cases B with
    | zero => cases h
    | @some xb yb hb =>
      have he : (xa, ya) = (xb, yb) := Option.some.inj h
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj he
      rfl

/-- Finiteness is obtained from coordinate encoding, not from enumerating a
large field or presupposing its curve order. -/
theorem points_finite : Finite W.toAffine.Point :=
  Finite.of_injective (pointCoordinates W) (pointCoordinates_injective W)

def pointFiberEncoding : W.toAffine.Point →
    Option (Σ x : K, {y : K // W.toAffine.Equation x y})
  | .zero => none
  | @Point.some _ _ _ x y h => some ⟨x, ⟨y, h.1⟩⟩

theorem pointFiberEncoding_injective : Function.Injective (pointFiberEncoding W) := by
  intro A B h
  apply pointCoordinates_injective W
  have he := congrArg (Option.map (fun z : Σ x : K, {y : K // W.toAffine.Equation x y} =>
    (z.1, z.2.1))) h
  cases A <;> cases B <;> exact he

theorem pointFiber_card_le_two (f : K → K)
    (hshape : ∀ x y, W.toAffine.Equation x y ↔ y ^ 2 = f x) (x : K) :
    Fintype.card {y : K // W.toAffine.Equation x y} ≤ 2 := by
  classical
  rw [Fintype.card_subtype]
  let q : K[X] := Polynomial.X ^ 2 - Polynomial.C (f x)
  have hq : q ≠ 0 := Polynomial.X_pow_sub_C_ne_zero (by norm_num) (f x)
  have hd : q.natDegree = 2 := Polynomial.natDegree_X_pow_sub_C
  have hc : (Finset.univ.filter (fun y => W.toAffine.Equation x y)).card ≤ q.natDegree := by
    by_contra h
    apply hq
    exact Polynomial.eq_zero_of_natDegree_lt_card_of_eval_eq_zero' q _
      (fun y hy => by
        have he := (hshape x y).mp (Finset.mem_filter.mp hy).2
        simp only [q, Polynomial.eval_sub, Polynomial.eval_pow,
          Polynomial.eval_X, Polynomial.eval_C, he, sub_self])
      (Nat.lt_of_not_ge h)
  simpa only [hd] using hc

/-- An unconditional geometric upper bound for a finite short Weierstrass
model, including the point at infinity. -/
theorem point_card_le (f : K → K)
    (hshape : ∀ x y, W.toAffine.Equation x y ↔ y ^ 2 = f x) :
    Nat.card W.toAffine.Point ≤ 2 * Fintype.card K + 1 := by
  classical
  letI : Finite W.toAffine.Point := points_finite W
  letI : Fintype W.toAffine.Point := Fintype.ofFinite _
  rw [Nat.card_eq_fintype_card]
  calc
    Fintype.card W.toAffine.Point ≤
        Fintype.card (Option (Σ x : K, {y : K // W.toAffine.Equation x y})) :=
      Fintype.card_le_of_injective (pointFiberEncoding W) (pointFiberEncoding_injective W)
    _ = (∑ x : K, Fintype.card {y : K // W.toAffine.Equation x y}) + 1 := by
      rw [Fintype.card_option, Fintype.card_sigma]
    _ ≤ (∑ _x : K, 2) + 1 :=
      Nat.add_le_add_right (Finset.sum_le_sum (fun x _ => pointFiber_card_le_two W f hshape x)) 1
    _ = 2 * Fintype.card K + 1 := by simp [mul_comm]

/-- Absence of roots of the curve's cubic excludes nonidentity two-torsion.
This theorem does not invoke any presumed group-order property. -/
theorem no_two_torsion_of_no_cubic_root (f : K → K)
    (hshape : ∀ x y, W.toAffine.Equation x y ↔ y ^ 2 = f x)
    (hneg : ∀ x y, W.toAffine.negY x y = -y)
    (hchar : (2 : K) ≠ 0) (hroot : ∀ x, f x ≠ 0)
    (A : W.toAffine.Point) (hA : 2 • A = 0) : A = 0 := by
  cases A with
  | zero => rfl
  | @some x y hp =>
    have he : (Point.some hp : W.toAffine.Point) = -Point.some hp :=
      eq_neg_of_add_eq_zero_left (by simpa only [two_nsmul] using hA)
    rw [Point.neg_some, Point.some.injEq] at he
    have hy : y = -y := by simpa only [hneg] using he.2
    have hz : y = 0 := by
      have hm : (2 : K) * y = 0 := by linear_combination hy
      exact (mul_eq_zero.mp hm).resolve_left hchar
    have hf := (hshape x y).mp hp.1
    exact False.elim (hroot x (by simpa only [hz, zero_pow (by norm_num : 2 ≠ 0)] using hf.symm))

end PointCounting

section FiniteGroup

variable {A : Type*} [AddGroup A] [Fintype A]

theorem card_odd_of_no_two_torsion
    (ht : ∀ a : A, 2 • a = 0 → a = 0) : Odd (Fintype.card A) := by
  classical
  by_contra ho
  have he := Nat.not_odd_iff_even.mp ho
  have hd : 2 ∣ Fintype.card A := even_iff_two_dvd.mp he
  letI : Fact (Nat.Prime 2) := ⟨Nat.prime_two⟩
  obtain ⟨a, ha⟩ := exists_prime_addOrderOf_dvd_card 2 hd
  have hm : 2 • a = 0 := by rw [← ha]; exact addOrderOf_nsmul_eq_zero a
  rw [ht a hm] at ha
  norm_num at ha

/-- A prime-order certified point and an odd small group cardinality determine
the whole group order. The input is a single checked scalar multiplication,
not an assumption that every point is killed by n. -/
theorem card_eq_prime_of_small_odd (n : ℕ) [Fact (Nat.Prime n)]
    (g : A) (hg : n • g = 0) (hg0 : g ≠ 0)
    (hsmall : Fintype.card A < 3 * n)
    (ht : ∀ a : A, 2 • a = 0 → a = 0) : Fintype.card A = n := by
  have hord : addOrderOf g = n := addOrderOf_eq_prime hg hg0
  have hd : n ∣ Fintype.card A := by rw [← hord]; exact addOrderOf_dvd_card
  obtain ⟨k, hk⟩ := hd
  have hc : Fintype.card A = n * k := hk
  have hp : 0 < Fintype.card A := Fintype.card_pos
  have hn : 0 < n := (Fact.out : Nat.Prime n).pos
  have hkpos : 0 < k := by
    by_contra h
    have hz : k = 0 := by omega
    rw [hc, hz, mul_zero] at hp
    omega
  have hklt : k < 3 := by
    apply (Nat.mul_lt_mul_left hn).mp
    simpa only [hc, Nat.mul_comm 3 n] using hsmall
  have hkodd : Odd k := by
    have ho := card_odd_of_no_two_torsion ht
    rw [hc] at ho
    exact (Nat.odd_mul.mp ho).2
  have hkone : k = 1 := by
    have ho := Nat.odd_iff.mp hkodd
    omega
  simpa only [hkone, mul_one] using hc

theorem all_nsmul_eq_zero_of_small_odd (n : ℕ) [Fact (Nat.Prime n)]
    (g : A) (hg : n • g = 0) (hg0 : g ≠ 0)
    (hsmall : Fintype.card A < 3 * n)
    (ht : ∀ a : A, 2 • a = 0 → a = 0) (a : A) : n • a = 0 := by
  have hc := card_eq_prime_of_small_odd n g hg hg0 hsmall ht
  rw [← hc]
  exact card_nsmul_eq_zero

end FiniteGroup

end ZolanaVE.ParameterCertificates
