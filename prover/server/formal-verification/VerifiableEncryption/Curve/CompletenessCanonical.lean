import VerifiableEncryption.Curve.Completeness

/-! Construct the actual P-256 canonical limb check from integer bounds. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

def zeroIndicator (value : F) : F := if value = 0 then 1 else 0

theorem zeroIndicator_spec (value : F) : Gates.is_zero value (zeroIndicator value) := by
  change (value ≠ 0 ∧ zeroIndicator value = 0) ∨ (value = 0 ∧ zeroIndicator value = 1)
  by_cases hv : value = 0 <;> simp [zeroIndicator, hv]

theorem zeroIndicator_native_spec (value : F) : GatesDef.is_zero value (zeroIndicator value) := by
  by_cases hv : value = 0 <;> simp [GatesDef.is_zero, zeroIndicator, hv]

theorem canonicalP_complete (L : List.Vector F 8)
    (hl : ∀ i, (L.get i).val < 2 ^ 32) (hv : limbNat L < p) :
    AssertCanonical_8_0_hc36017e9 L := by
  have hmax : ∀ i, (4294967295 : F) - L.get i = 0 ↔ (L.get i).val = 4294967295 := by
    intro i
    rw [sub_eq_zero]
    constructor
    · intro he
      rw [← he]
      exact ZMod.val_cast_of_lt (lt_order_of_le (by norm_num))
    · intro he
      rw [eq_natCast_val (L.get i), he]
      rfl
  have h0 := hl 0; have h1 := hl 1; have h2 := hl 2; have h3 := hl 3
  have h4 := hl 4; have h5 := hl 5; have h6 := hl 6; have h7 := hl 7
  have hbound := hv
  norm_num [limbNat, Fin.sum_univ_eight, p,
    Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod] at hbound
  have h6cases : (L.get 7).val = 4294967295 → (L.get 6).val = 0 ∨ (L.get 6).val = 1 := by
    intro he
    norm_num at h0 h1 h2 h3 h4 h5 h6 h7
    omega
  have hmiddle : (L.get 7).val = 4294967295 → (L.get 6).val = 1 →
      (L.get 5).val = 0 ∧ (L.get 4).val = 0 ∧ (L.get 3).val = 0 := by
    intro he7 he6
    norm_num at h0 h1 h2 h3 h4 h5 h6 h7
    omega
  have hlast : (L.get 7).val = 4294967295 → (L.get 6).val = 1 →
      (L.get 2).val = 4294967295 → (L.get 1).val = 4294967295 →
      (L.get 0).val ≠ 4294967295 := by
    intro he7 he6 he2 he1
    norm_num at h0 h1 h2 h3 h4 h5 h6 h7
    simp only [List.Vector.get_zero]
    omega
  have hnative : ∀ i n, (L.get i).val = n → L.get i = (n : F) := by
    intro i n he
    rw [eq_natCast_val (L.get i), he]
  let high := (4294967295 : F) - L.get 7
  let low := (4294967295 : F) - L.get 2 + ((4294967295 : F) - L.get 1)
  let last := (4294967295 : F) - L.get 0
  unfold AssertCanonical_8_0_hc36017e9
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, GatesDef.eq, exists_eq_left]
  refine ⟨zeroIndicator high, ?_, ?_, ?_, zeroIndicator low, ?_, zeroIndicator last, ?_, ?_, trivial⟩
  · simpa [high, GatesDef.is_zero] using zeroIndicator_native_spec high
  · by_cases he : high = 0
    · have hv7 := (hmax 7).mp he
      rcases h6cases hv7 with hv6 | hv6 <;>
        simp [zeroIndicator, he, hnative 6 _ hv6]
    · simp [zeroIndicator, he]
  · by_cases he : high = 0
    · have hv7 := (hmax 7).mp he
      rcases h6cases hv7 with hv6 | hv6
      · simp [zeroIndicator, he, hnative 6 _ hv6]
      · obtain ⟨hv5, hv4, hv3⟩ := hmiddle hv7 hv6
        simp [zeroIndicator, he, hnative 5 _ hv5, hnative 4 _ hv4, hnative 3 _ hv3]
    · simp [zeroIndicator, he]
  · simpa [low, GatesDef.is_zero] using zeroIndicator_native_spec low
  · simpa [last, GatesDef.is_zero] using zeroIndicator_native_spec last
  · by_cases he : high = 0
    · have hv7 := (hmax 7).mp he
      rcases h6cases hv7 with hv6 | hv6
      · simp [zeroIndicator, he, hnative 6 _ hv6]
      · by_cases hlo : low = 0
        · let gap : ℕ := 4294967295 - (L.get 2).val + (4294967295 - (L.get 1).val)
          have hgap : gap < Order := lt_order_of_le (by dsimp [gap]; norm_num; omega)
          have hgapF : (gap : F) = low := by
            dsimp [gap, low]
            rw [Nat.cast_add, Nat.cast_sub (by norm_num at h2; omega),
              Nat.cast_sub (by norm_num at h1; omega)]
            rw [← eq_natCast_val (L.get 2), ← eq_natCast_val (L.get 1)]
            norm_num
          have hg0 : gap = 0 := natCast_inj hgap (lt_order_of_le (by norm_num))
            (by rw [hgapF, hlo]; simp)
          have he2 : (L.get 2).val = 4294967295 := by
            dsimp [gap] at hg0
            norm_num at h1 h2
            omega
          have he1 : (L.get 1).val = 4294967295 := by
            dsimp [gap] at hg0
            norm_num at h1 h2
            omega
          have hlastNe : last ≠ 0 := by
            intro hlast0
            exact hlast hv7 hv6 he2 he1 ((hmax 0).mp hlast0)
          simp [zeroIndicator, he, hlastNe]
        · simp [zeroIndicator, he, hlo]
    · simp [zeroIndicator, he]

/-- The native squared-limb sum cannot wrap: every integer summand is at
most (2^32-1)^2 and there are exactly eight. Different integer coordinates
therefore construct a valid actual distinct-x guard. -/
theorem distinctX_sum_nonzero (L R : List.Vector F 8)
    (hl : ∀ i, (L.get i).val < 2 ^ 32) (hr : ∀ i, (R.get i).val < 2 ^ 32)
    (hne : limbNat L ≠ limbNat R) : ∑ i : Fin 8, (L.get i - R.get i) ^ 2 ≠ 0 := by
  let S : ℤ := ∑ i : Fin 8, (((L.get i).val : ℤ) - ((R.get i).val : ℤ)) ^ 2
  let B : ℤ := 2 ^ 32 - 1
  have hS0 : 0 ≤ S := Finset.sum_nonneg (fun i hi => sq_nonneg _)
  have hSpos : 0 < S := by
    by_contra hp
    have hz : S = 0 := by omega
    have hparts := (Finset.sum_eq_zero_iff_of_nonneg (fun i hi => sq_nonneg
      (((L.get i).val : ℤ) - ((R.get i).val : ℤ)))).mp hz
    have he : ∀ i : Fin 8, (L.get i).val = (R.get i).val := by
      intro i
      have hs := hparts i (Finset.mem_univ i)
      have hi : ((L.get i).val : ℤ) = ((R.get i).val : ℤ) := by nlinarith
      exact_mod_cast hi
    apply hne
    unfold limbNat
    simp only [he]
  have hEach : ∀ i : Fin 8,
      (((L.get i).val : ℤ) - ((R.get i).val : ℤ)) ^ 2 ≤ B ^ 2 := by
    intro i
    have hli : ((L.get i).val : ℤ) < 2 ^ 32 := by exact_mod_cast hl i
    have hri : ((R.get i).val : ℤ) < 2 ^ 32 := by exact_mod_cast hr i
    have hln := Int.natCast_nonneg (L.get i).val
    have hrn := Int.natCast_nonneg (R.get i).val
    have hminus : 0 ≤ B - (((L.get i).val : ℤ) - ((R.get i).val : ℤ)) := by dsimp [B]; omega
    have hplus : 0 ≤ B + (((L.get i).val : ℤ) - ((R.get i).val : ℤ)) := by dsimp [B]; omega
    have hp := mul_nonneg hminus hplus
    nlinarith
  have hSbound : S ≤ 8 * B ^ 2 := by
    calc
      S ≤ ∑ i : Fin 8, B ^ 2 := Finset.sum_le_sum (fun i hi => hEach i)
      _ = 8 * B ^ 2 := by simp
  have hlift : |S| < (Order : ℤ) := by
    rw [abs_of_pos hSpos]
    exact lt_of_le_of_lt hSbound (by norm_num [B, Order])
  have hcast : (S : F) = ∑ i : Fin 8, (L.get i - R.get i) ^ 2 := by
    dsimp [S]
    push_cast
    simp only [ZMod.natCast_zmod_val]
  intro hz
  have hi : S = 0 := int_eq_zero_of_cast (hcast.trans hz) hlift
  omega

theorem distinctX_values_complete (L R : List.Vector F 8)
    (hl : ∀ i, (L.get i).val < 2 ^ 32) (hr : ∀ i, (R.get i).val < 2 ^ 32)
    (hlp : limbNat L < p) (hrp : limbNat R < p) (hne : limbNat L ≠ limbNat R) :
    AssertDistinctX_8_8_h83dcf683 L R :=
  distinctX_complete L R (canonicalP_complete L hl hlp) (canonicalP_complete R hr hrp)
    (distinctX_sum_nonzero L R hl hr hne)

/-- Construct the actual same-x Boolean and inverse-of-squared-differences
witness used by completeAdd. Equality of bounded limb values determines the
branch; no equality-test hint correctness is assumed. -/
theorem sameX_native_witness (L R : List.Vector F 8)
    (hl : ∀ i, (L.get i).val < 2 ^ 32) (hr : ∀ i, (R.get i).val < 2 ^ 32) :
    ∃ sameX : Bool, ∃ inverse : F,
      GatesDef.is_bool (if sameX then (1 : F) else 0) ∧
      (∑ i : Fin 8, (L.get i - R.get i) ^ 2) * inverse =
        1 - (if sameX then 1 else 0) ∧
      (sameX = true ↔ limbNat L = limbNat R) := by
  by_cases he : limbNat L = limbNat R
  · refine ⟨true, 0, by simp [GatesDef.is_bool], ?_, by simp [he]⟩
    simp
  · have hd := distinctX_sum_nonzero L R hl hr he
    refine ⟨false, (∑ i : Fin 8, (L.get i - R.get i) ^ 2)⁻¹,
      by simp [GatesDef.is_bool], ?_, by simp [he]⟩
    simpa using mul_inv_cancel₀ hd

end ZolanaVE.P256.Completeness
