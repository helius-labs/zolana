import VerifiableEncryption.Curve.Ladder
import VerifiableEncryption.Curve.CompletenessLadderDecomposition

/-!
Mathematical exceptional-scalar selection and initial slot finiteness.
The six residues are exactly ±1, ±3 and ±1/3. Halving an exceptional residue
leaves this set, and doubling the input preserves the scalar product.
No extracted selector/lookup or slope witness is assumed here.
-/

namespace ZolanaVE.P256.Completeness

abbrev ScalarField := ZMod n

def Exceptional (s : ScalarField) : Prop :=
  s = 1 ∨ s = -1 ∨ s = 3 ∨ s = -3 ∨ s = 1 / 3 ∨ s = -(1 / 3)

instance (s : ScalarField) : Decidable (Exceptional s) :=
  inferInstanceAs (Decidable
    (s = 1 ∨ s = -1 ∨ s = 3 ∨ s = -3 ∨ s = 1 / 3 ∨ s = -(1 / 3)))

theorem scalar_two_ne_zero : (2 : ScalarField) ≠ 0 := by decide +kernel
theorem scalar_three_ne_zero : (3 : ScalarField) ≠ 0 := by decide +kernel

theorem exceptional_half_not_exceptional {s : ScalarField} (hs : Exceptional s) :
    ¬Exceptional (s / 2) := by
  rcases hs with rfl | rfl | rfl | rfl | rfl | rfl <;> decide +kernel

theorem exceptional_neg_iff (s : ScalarField) : Exceptional (-s) ↔ Exceptional s := by
  simp only [Exceptional, neg_eq_iff_eq_neg, neg_neg]
  tauto

def selectedScalar (s : ScalarField) : ScalarField := if Exceptional s then s / 2 else s

theorem selectedScalar_nonzero {s : ScalarField} (hs : s ≠ 0) : selectedScalar s ≠ 0 := by
  unfold selectedScalar
  split_ifs
  · exact div_ne_zero hs scalar_two_ne_zero
  · exact hs

theorem selectedScalar_not_exceptional (s : ScalarField) : ¬Exceptional (selectedScalar s) := by
  unfold selectedScalar
  split_ifs with h
  · exact exceptional_half_not_exceptional h
  · exact h

noncomputable def selectedPoint (s : ScalarField) (Q : P) : P :=
  if Exceptional s then 2 • Q else Q

theorem selectedPoint_nonzero (s : ScalarField) {Q : P} (hq : Q ≠ 0) :
    selectedPoint s Q ≠ 0 := by
  unfold selectedPoint
  split_ifs
  · intro hz
    exact hq (no_two_torsion Q hz)
  · exact hq

/-- Exact scalar-field equality characterizes collisions on a nonzero point. -/
theorem scalar_faithful {Q : P} (hq : Q ≠ 0) (a c : ℤ) :
    a • Q = c • Q ↔ (a : ScalarField) = (c : ScalarField) := by
  have hord : addOrderOf Q = n :=
    addOrderOf_eq_prime (Assumptions.p256_point_order Q) hq
  rw [zsmul_eq_zsmul_iff_modEq, hord]
  exact (ZMod.intCast_eq_intCast_iff a c n).symm

theorem scalar_product_nonzero {Q : P} (hq : Q ≠ 0) {scalar : ℤ}
    (hs : (scalar : ScalarField) ≠ 0) : scalar • Q ≠ 0 := by
  intro hz
  have he := (scalar_faithful hq scalar 0).mp (by simpa using hz)
  exact hs (by simpa using he)

/-- The concrete canonical representatives of the selected scalar/point
multiply to the original product, including all six exceptional branches. -/
theorem selected_product_eq (s : ScalarField) {Q : P} (hq : Q ≠ 0) :
    (selectedScalar s).val • selectedPoint s Q = s.val • Q := by
  by_cases hs : Exceptional s
  · simp only [selectedScalar, selectedPoint, if_pos hs, smul_smul]
    have hfield : (((s / 2).val * 2 : ℕ) : ScalarField) = (s.val : ScalarField) := by
      simp only [Nat.cast_mul, ZMod.natCast_zmod_val, Nat.cast_ofNat]
      exact div_mul_cancel₀ s scalar_two_ne_zero
    have h := (scalar_faithful hq (((s / 2).val * 2 : ℕ) : ℤ) (s.val : ℤ)).mpr
      (by simpa only [Int.cast_natCast] using hfield)
    simpa only [natCast_zsmul] using h
  · simp only [selectedScalar, selectedPoint, if_neg hs]

/-- Our constructed decomposition gives the exact joint-ladder relation for
the chosen true, sign-corrected product. This is not read from circuit constraints. -/
theorem ladder_relation_of_decomposition (Q : P) (scalar : ℤ) (num den : ℕ) (sign : Bool)
    (hdec : scalar * ((if sign then -1 else 1 : ℤ) * den) + num ≡ 0 [ZMOD n]) :
    (num : ℤ) • Q + (den : ℤ) •
      ((if sign then -1 else 1 : ℤ) • (scalar • Q)) = 0 := by
  simp only [smul_smul]
  rw [← add_zsmul]
  have hc : (num : ℤ) + (den : ℤ) * ((if sign then -1 else 1 : ℤ) * scalar) =
      scalar * ((if sign then -1 else 1 : ℤ) * den) + num := by ring
  rw [hc]
  simpa only [zero_zsmul] using zsmul_congr hdec Q

/-- All six initial group collisions are excluded by the selected residue. -/
theorem ladder_initial_collisions {Q : P} (hq : Q ≠ 0) (scalar : ℤ)
    (hs : ¬Exceptional (scalar : ScalarField)) :
    scalar • Q ≠ Q ∧ scalar • Q ≠ -Q ∧
    scalar • Q ≠ 3 • Q ∧ scalar • Q ≠ -(3 • Q) ∧
    3 • (scalar • Q) ≠ Q ∧ 3 • (scalar • Q) ≠ -Q := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro he
    have hf := (scalar_faithful hq scalar 1).mp (by simpa using he)
    exact hs (Or.inl (by simpa using hf))
  · intro he
    have hf := (scalar_faithful hq scalar (-1)).mp (by simpa using he)
    exact hs (Or.inr (Or.inl (by simpa using hf)))
  · intro he
    have hf := (scalar_faithful hq scalar 3).mp (by simpa only [natCast_zsmul] using he)
    exact hs (Or.inr (Or.inr (Or.inl (by simpa using hf))))
  · intro he
    have hf := (scalar_faithful hq scalar (-3)).mp
      (by simpa only [neg_zsmul, natCast_zsmul] using he)
    exact hs (Or.inr (Or.inr (Or.inr (Or.inl (by simpa using hf)))))
  · intro he
    have hf := (scalar_faithful hq (3 * scalar) 1).mp
      (by simpa only [mul_zsmul, natCast_zsmul, one_zsmul] using he)
    have hfrac : (scalar : ScalarField) = 1 / 3 := by
      apply (eq_div_iff scalar_three_ne_zero).mpr
      simpa only [Int.cast_mul, Int.cast_ofNat, Int.cast_one, mul_comm] using hf
    exact hs (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl hfrac)))))
  · intro he
    have hf := (scalar_faithful hq (3 * scalar) (-1)).mp
      (by simpa only [mul_zsmul, natCast_zsmul, neg_one_zsmul] using he)
    have hfrac : (scalar : ScalarField) = (-1) / 3 := by
      apply (eq_div_iff scalar_three_ne_zero).mpr
      simpa only [Int.cast_mul, Int.cast_ofNat, Int.cast_neg, Int.cast_one, mul_comm] using hf
    exact hs (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (by simpa only [neg_div] using hfrac))))))

theorem ladder_slots_nonzero {Q : P} (hq : Q ≠ 0) (scalar : ℤ)
    (hs : ¬Exceptional (scalar : ScalarField)) :
    ∀ slot, slot < 8 → Ladder.slotPoint slot Q (scalar • Q) ≠ 0 := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := ladder_initial_collisions hq scalar hs
  exact Ladder.slots_nonzero h1 h2 h3 h4 h5 h6

/-- The inverse-four repair makes the eager discarded add use R, whose x
coordinate differs from both 3R and 4R for every nonzero R. -/
theorem correction_product_distinct {R : P} (hr : R ≠ 0) :
    R ≠ 3 • R ∧ R ≠ -(3 • R) ∧ R ≠ 4 • R ∧ R ≠ -(4 • R) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro he
    have hf := (scalar_faithful hr 1 3).mp
      (by simpa only [one_zsmul, natCast_zsmul] using he)
    exact (by decide +kernel : (1 : ScalarField) ≠ 3) (by simpa using hf)
  · intro he
    have hf := (scalar_faithful hr 1 (-3)).mp
      (by simpa only [one_zsmul, neg_zsmul, natCast_zsmul] using he)
    exact (by decide +kernel : (1 : ScalarField) ≠ -3) (by simpa using hf)
  · intro he
    have hf := (scalar_faithful hr 1 4).mp
      (by simpa only [one_zsmul, natCast_zsmul] using he)
    exact (by decide +kernel : (1 : ScalarField) ≠ 4) (by simpa using hf)
  · intro he
    have hf := (scalar_faithful hr 1 (-4)).mp
      (by simpa only [one_zsmul, neg_zsmul, natCast_zsmul] using he)
    exact (by decide +kernel : (1 : ScalarField) ≠ -4) (by simpa using hf)

theorem primitive_den_odd_of_num_even (num den : ℕ) (hc : Nat.Coprime num den)
    (he : num % 2 = 0) : den % 2 = 1 := by
  have htwo : Nat.Coprime 2 den :=
    Nat.Coprime.of_dvd_left (Nat.dvd_of_mod_eq_zero he) hc
  exact Nat.odd_iff.mp (Nat.coprime_two_left.mp htwo)

/-- Both the selected and discarded low-bit additions have x-distinct
operands. The num-even/den-even case is impossible for our primitive pair.
This includes the repaired inverse-four eager branch, not only the selected sum. -/
theorem lowbit_correction_distinct {Q R : P} (hr : R ≠ 0)
    (h3 : 3 • R ≠ Q) (hneg3 : 3 • R ≠ -Q)
    (num den : ℕ) (hc : Nat.Coprime num den) :
    let target := if den % 2 = 1 then 3 • R else 4 • R
    let addend := if num % 2 = 1 then R else Q
    addend ≠ target ∧ addend ≠ -target := by
  obtain ⟨hr3, hrn3, hr4, hrn4⟩ := correction_product_distinct hr
  by_cases hn : num % 2 = 1
  · by_cases hd : den % 2 = 1
    · simpa only [if_pos hn, if_pos hd] using ⟨hr3, hrn3⟩
    · simpa only [if_pos hn, if_neg hd] using ⟨hr4, hrn4⟩
  · have he : num % 2 = 0 := by omega
    have hd := primitive_den_odd_of_num_even num den hc he
    simp only [if_neg hn, if_pos hd]
    constructor
    · exact h3.symm
    · intro h
      exact hneg3 (by rw [h, neg_neg])

end ZolanaVE.P256.Completeness
