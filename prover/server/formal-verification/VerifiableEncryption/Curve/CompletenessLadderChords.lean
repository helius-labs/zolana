import VerifiableEncryption.Curve.CompletenessLadderPrefixes

/-!
Middle-step chord noncollision for primitive joint-ladder recoding.
The two possible collisions use coefficients newPrefix-2*oldPrefix and
6*oldPrefix-newPrefix. The first is always smaller than a value >1; the
second is smaller than a value >=6, with the remaining values checked by
finite arithmetic cases. Both determinants are far below n after prefix
cancellation. This proves a mathematical chord denominator property, not
the stronger native distinct-slope guard or an extracted gadget witness.
-/

namespace ZolanaVE.P256.Completeness

def forwardChordCoefficient (value divisor : ℕ) : ℤ :=
  (prefixCoefficient value divisor : ℤ) - 2 * (prefixCoefficient value (4 * divisor) : ℤ)

def backwardChordCoefficient (value divisor : ℕ) : ℤ :=
  6 * (prefixCoefficient value (4 * divisor) : ℤ) - (prefixCoefficient value divisor : ℤ)

theorem forwardChordCoefficient_nonzero (value divisor : ℕ) :
    forwardChordCoefficient value divisor ≠ 0 := by
  simp only [forwardChordCoefficient, prefixCoefficient, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]
  omega

theorem backwardChordCoefficient_nonzero (value divisor : ℕ) :
    backwardChordCoefficient value divisor ≠ 0 := by
  simp only [backwardChordCoefficient, prefixCoefficient, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]
  omega

theorem forwardChordCoefficient_small (value divisor : ℕ) (hv : 1 < value) (hd : 2 ≤ divisor) :
    |forwardChordCoefficient value divisor| < (value : ℤ) := by
  have hquot : value / divisor / 4 = value / (4 * divisor) := by
    rw [Nat.div_div_eq_div_mul, Nat.mul_comm divisor 4]
  have hq := Nat.mul_div_le (value / divisor) 4
  rw [hquot] at hq
  have hm := Nat.mul_le_mul_right (value / divisor) (show 2 ≤ divisor by omega)
  have hval := Nat.mul_div_le value divisor
  rw [abs_lt]
  simp only [forwardChordCoefficient, prefixCoefficient, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]
  omega

theorem backwardChordCoefficient_formula (value divisor : ℕ) :
    backwardChordCoefficient value divisor =
      4 * ((value / (4 * divisor) : ℕ) : ℤ) + 5 -
        2 * ((value / divisor % 4 : ℕ) : ℤ) := by
  have hquot : value / divisor / 4 = value / (4 * divisor) := by
    rw [Nat.div_div_eq_div_mul, Nat.mul_comm divisor 4]
  have hn := Nat.div_add_mod (value / divisor) 4
  rw [hquot] at hn
  rw [Nat.mul_comm 4 (value / (4 * divisor))] at hn
  have hc : ((value / (4 * divisor) : ℕ) : ℤ) * 4 +
      ((value / divisor % 4 : ℕ) : ℤ) = ((value / divisor : ℕ) : ℤ) := by
    exact_mod_cast hn
  simp only [backwardChordCoefficient, prefixCoefficient, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]
  omega

theorem backwardChordCoefficient_small (value divisor : ℕ) (hv : 6 ≤ value) (hd : 4 ≤ divisor) :
    |backwardChordCoefficient value divisor| < (value : ℤ) := by
  have hm := Nat.mul_le_mul_right (value / (4 * divisor))
    (show 16 ≤ 4 * divisor by omega)
  have hval := Nat.mul_div_le value (4 * divisor)
  have hr : value / divisor % 4 < 4 := Nat.mod_lt _ (by decide)
  rw [backwardChordCoefficient_formula, abs_lt]
  by_cases hz : value / (4 * divisor) = 0
  · omega
  · omega

/-- A small nonzero coefficient cannot belong to a primitive zero determinant. -/
theorem primitive_determinant_nonzero_of_small (num den : ℕ) (u v : ℤ)
    (hc : Nat.Coprime num den) (hu : u ≠ 0) (hsmall : |u| < (num : ℤ)) :
    u * den - v * num ≠ 0 := by
  intro hz
  have he : u * (den : ℤ) = v * num := sub_eq_zero.mp hz
  have hdvd : (num : ℤ) ∣ u :=
    hc.isCoprime.dvd_of_dvd_mul_right (he.symm ▸ dvd_mul_left (num : ℤ) v)
  have habsDvd : num ∣ u.natAbs := by
    simpa only [Int.natAbs_ofNat] using Int.natAbs_dvd_natAbs.mpr hdvd
  have habsPos : 0 < u.natAbs := by
    apply Nat.pos_of_ne_zero
    exact Int.natAbs_ne_zero.mpr hu
  have habsSmall : u.natAbs < num := by
    have h : (u.natAbs : ℤ) < (num : ℤ) := by
      simpa only [Int.natCast_natAbs] using hsmall
    exact_mod_cast h
  exact (not_le_of_gt habsSmall) (Nat.le_of_dvd habsPos habsDvd)

theorem forwardChordDeterminant_nonzero (num den divisor : ℕ)
    (hn : 0 < num) (hd : 0 < den) (hdiv : 4 ≤ divisor)
    (hc : Nat.Coprime num den) (hpair : num ≠ 1 ∨ den ≠ 1) :
    forwardChordCoefficient num divisor * den - forwardChordCoefficient den divisor * num ≠ 0 := by
  rcases hpair with hnum | hden
  · exact primitive_determinant_nonzero_of_small num den _ _ hc
      (forwardChordCoefficient_nonzero num divisor)
      (forwardChordCoefficient_small num divisor (by omega) (by omega))
  · have h := primitive_determinant_nonzero_of_small den num
      (forwardChordCoefficient den divisor) (forwardChordCoefficient num divisor) hc.symm
      (forwardChordCoefficient_nonzero den divisor)
      (forwardChordCoefficient_small den divisor (by omega) (by omega))
    intro hz
    apply h
    linear_combination -hz

theorem backwardChordDeterminant_nonzero (num den divisor : ℕ)
    (hn : 0 < num) (hd : 0 < den) (hdiv : 4 ≤ divisor)
    (hc : Nat.Coprime num den) (hpair : num ≠ 1 ∨ den ≠ 1) :
    backwardChordCoefficient num divisor * den - backwardChordCoefficient den divisor * num ≠ 0 := by
  intro hz
  have hnum : num < 6 := by
    by_contra h
    exact primitive_determinant_nonzero_of_small num den _ _ hc
      (backwardChordCoefficient_nonzero num divisor)
      (backwardChordCoefficient_small num divisor (by omega) hdiv) hz
  have hden : den < 6 := by
    by_contra h
    apply primitive_determinant_nonzero_of_small den num
      (backwardChordCoefficient den divisor) (backwardChordCoefficient num divisor) hc.symm
      (backwardChordCoefficient_nonzero den divisor)
      (backwardChordCoefficient_small den divisor (by omega) hdiv)
    linear_combination -hz
  by_cases hlarge : 6 ≤ divisor
  · have hnumDiv : num / divisor = 0 := Nat.div_eq_of_lt (by omega)
    have hdenDiv : den / divisor = 0 := Nat.div_eq_of_lt (by omega)
    have hnumOld : num / (4 * divisor) = 0 := Nat.div_eq_of_lt (by omega)
    have hdenOld : den / (4 * divisor) = 0 := Nat.div_eq_of_lt (by omega)
    simp only [backwardChordCoefficient, prefixCoefficient, hnumDiv, hdenDiv,
      hnumOld, hdenOld, mul_zero, zero_add, Nat.cast_one] at hz
    have he : num = den := by omega
    subst den
    have hone : num = 1 := by simpa only [Nat.Coprime, Nat.gcd_self] using hc
    exact hpair.elim (fun h => h hone) (fun h => h hone)
  · interval_cases num <;> interval_cases den <;> interval_cases divisor <;>
      norm_num [backwardChordCoefficient, prefixCoefficient] at hz hc hpair

theorem forwardChordDeterminant_bound (num den divisor : ℕ) (hdiv : 0 < divisor) :
    |forwardChordCoefficient num divisor * den - forwardChordCoefficient den divisor * num| ≤
      3 * ((num : ℤ) + den) := by
  have hi : forwardChordCoefficient num divisor * den - forwardChordCoefficient den divisor * num =
      prefixDeterminant num den divisor - 2 * prefixDeterminant num den (4 * divisor) := by
    unfold forwardChordCoefficient prefixDeterminant
    ring
  rw [hi]
  have hs := abs_sub (prefixDeterminant num den divisor)
    (2 * prefixDeterminant num den (4 * divisor))
  rw [abs_mul, show |(2 : ℤ)| = 2 by norm_num] at hs
  have hn := prefixDeterminant_abs_le num den divisor hdiv
  have hd := prefixDeterminant_abs_le num den (4 * divisor) (by omega)
  linarith

theorem backwardChordDeterminant_bound (num den divisor : ℕ) (hdiv : 0 < divisor) :
    |backwardChordCoefficient num divisor * den - backwardChordCoefficient den divisor * num| ≤
      7 * ((num : ℤ) + den) := by
  have hi : backwardChordCoefficient num divisor * den - backwardChordCoefficient den divisor * num =
      6 * prefixDeterminant num den (4 * divisor) - prefixDeterminant num den divisor := by
    unfold backwardChordCoefficient prefixDeterminant
    ring
  rw [hi]
  have hs := abs_sub (6 * prefixDeterminant num den (4 * divisor))
    (prefixDeterminant num den divisor)
  rw [abs_mul, show |(6 : ℤ)| = 6 by norm_num] at hs
  have hn := prefixDeterminant_abs_le num den divisor hdiv
  have hd := prefixDeterminant_abs_le num den (4 * divisor) (by omega)
  linarith

theorem combination_nonzero_of_small_determinant {Q R : P} (hq : Q ≠ 0)
    (num den : ℕ) (u v : ℤ)
    (hrel : (num : ℤ) • Q + (den : ℤ) • R = 0)
    (hnz : u * den - v * num ≠ 0) (hsmall : |u * den - v * num| < (n : ℤ)) :
    u • Q + v • R ≠ 0 := by
  have hr : (den : ℤ) • R = -((num : ℤ) • Q) := eq_neg_of_add_eq_zero_right hrel
  have hg : (den : ℤ) • (u • Q + v • R) = (u * den - v * num) • Q := by
    calc
      _ = ((den : ℤ) * u) • Q + v • ((den : ℤ) • R) := by
        simp only [zsmul_add, ← mul_zsmul]
        rw [mul_comm (den : ℤ) v]
      _ = ((den : ℤ) * u) • Q - (v * num) • Q := by
        rw [hr, zsmul_neg, ← mul_zsmul, sub_eq_add_neg]
      _ = _ := by
        rw [sub_eq_add_neg, ← sub_zsmul]
        congr 1
        ring
  intro hz
  rw [hz, zsmul_zero] at hg
  have he := (scalar_faithful hq (u * den - v * num) 0).mp (by simpa using hg.symm)
  have hzmod : ((u * (den : ℤ) - v * (num : ℤ) : ℤ) : ScalarField) = 0 := by
    simpa using he
  have hdvd := (ZMod.intCast_zmod_eq_zero_iff_dvd _ n).mp hzmod
  have habs : (u * den - v * num).natAbs < Int.natAbs (n : ℤ) := by
    have h : ((u * den - v * num).natAbs : ℤ) < (n : ℤ) := by
      simpa only [Int.natCast_natAbs] using hsmall
    exact_mod_cast h
  exact hnz (Int.eq_zero_of_dvd_of_natAbs_lt_natAbs hdvd habs)

noncomputable def middleAccumulator (num den divisor : ℕ) (Q R : P) : P :=
  (prefixCoefficient num (4 * divisor) : ℤ) • Q +
    (prefixCoefficient den (4 * divisor) : ℤ) • R

noncomputable def middleRow (num den divisor : ℕ) (Q R : P) : P :=
  ((prefixCoefficient num divisor : ℤ) - 4 * (prefixCoefficient num (4 * divisor) : ℤ)) • Q +
    ((prefixCoefficient den divisor : ℤ) - 4 * (prefixCoefficient den (4 * divisor) : ℤ)) • R

/-- The row has exactly the ±1/±3 two-bit coefficients used by the table. -/
theorem middleRow_coefficients (num den divisor : ℕ) (Q R : P) :
    middleRow num den divisor Q R =
      (2 * ((num / divisor % 4 : ℕ) : ℤ) - 3) • Q +
        (2 * ((den / divisor % 4 : ℕ) : ℤ) - 3) • R := by
  unfold middleRow
  rw [prefixCoefficient_step num divisor, prefixCoefficient_step den divisor]
  congr 1 <;> congr 1 <;> ring

/-- Both possible x-collisions between 2A and a middle row are excluded by
the primitive decomposition. This remains separate from native slope checks. -/
theorem middle_chord_noncollision {Q R : P} (hq : Q ≠ 0)
    (num den divisor : ℕ) (hn0 : 0 < num) (hd0 : 0 < den)
    (hn : num < 2 ^ 129) (hd : den < 2 ^ 129) (hdiv : 4 ≤ divisor)
    (hc : Nat.Coprime num den) (hpair : num ≠ 1 ∨ den ≠ 1)
    (hrel : (num : ℤ) • Q + (den : ℤ) • R = 0) :
    (2 : ℤ) • middleAccumulator num den divisor Q R ≠ middleRow num den divisor Q R ∧
    (2 : ℤ) • middleAccumulator num den divisor Q R ≠ -middleRow num den divisor Q R := by
  have hcap : 7 * (2 * (2 : ℕ) ^ 129) < n := by norm_num [n]
  have hsmall : 7 * ((num : ℤ) + den) < (n : ℤ) := by
    have hnat : 7 * (num + den) < n := by omega
    exact_mod_cast hnat
  have hsumNonneg : (0 : ℤ) ≤ (num : ℤ) + den := by positivity
  have hb : backwardChordCoefficient num divisor • Q + backwardChordCoefficient den divisor • R ≠ 0 :=
    combination_nonzero_of_small_determinant hq num den _ _ hrel
      (backwardChordDeterminant_nonzero num den divisor hn0 hd0 hdiv hc hpair)
      (lt_of_le_of_lt (backwardChordDeterminant_bound num den divisor (by omega)) hsmall)
  have hf : forwardChordCoefficient num divisor • Q + forwardChordCoefficient den divisor • R ≠ 0 :=
    combination_nonzero_of_small_determinant hq num den _ _ hrel
      (forwardChordDeterminant_nonzero num den divisor hn0 hd0 hdiv hc hpair)
      (lt_of_le_of_lt (forwardChordDeterminant_bound num den divisor (by omega))
        (by linarith [hsmall]))
  constructor
  · intro h
    apply hb
    have hz := sub_eq_zero.mpr h
    convert hz using 1 <;>
      simp only [backwardChordCoefficient, middleAccumulator, middleRow,
        sub_zsmul, mul_zsmul, zsmul_add, zsmul_sub] <;> abel
  · intro h
    apply hf
    have hz : (2 : ℤ) • middleAccumulator num den divisor Q R + middleRow num den divisor Q R = 0 := by
      rw [h, neg_add_cancel]
    convert hz using 1 <;>
      simp only [forwardChordCoefficient, middleAccumulator, middleRow,
        sub_zsmul, mul_zsmul, zsmul_add, zsmul_sub] <;> abel

theorem row_digits_of_words (nq nr : ℕ) (hq : nq < 4) (hr : nr < 4) :
    Ladder.digQ (nq / 2 + 2 * (nr / 2) + 4 * (nq % 2) + 8 * (nr % 2)) =
        2 * (nq : ℤ) - 3 ∧
      Ladder.digR (nq / 2 + 2 * (nr / 2) + 4 * (nq % 2) + 8 * (nr % 2)) =
        2 * (nr : ℤ) - 3 := by
  interval_cases nq <;> interval_cases nr <;> norm_num [Ladder.digQ, Ladder.digR]

theorem middleRow_nonzero {Q : P} (hq : Q ≠ 0) (scalar : ℤ)
    (hs : ¬Exceptional (scalar : ScalarField)) (num den divisor : ℕ) :
    middleRow num den divisor Q (scalar • Q) ≠ 0 := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := ladder_initial_collisions hq scalar hs
  let nq := num / divisor % 4
  let nr := den / divisor % 4
  have hnq : nq < 4 := Nat.mod_lt _ (by decide)
  have hnr : nr < 4 := Nat.mod_lt _ (by decide)
  let idx := nq / 2 + 2 * (nr / 2) + 4 * (nq % 2) + 8 * (nr % 2)
  have hi : idx < 16 := by
    dsimp [idx]
    have hqmod := Nat.mod_lt nq (by decide : 0 < 2)
    have hrmod := Nat.mod_lt nr (by decide : 0 < 2)
    omega
  have ht := Ladder.rows_nonzero h1 h2 h3 h4 h5 h6 idx hi
  have digits := row_digits_of_words nq nr hnq hnr
  have he : middleRow num den divisor Q (scalar • Q) = Ladder.rowPoint idx Q (scalar • Q) := by
    rw [middleRow_coefficients, Ladder.row_point Q (scalar • Q) idx hi]
    change (2 * (nq : ℤ) - 3) • Q + (2 * (nr : ℤ) - 3) • (scalar • Q) = _
    rw [digits.1, digits.2]
  rw [he]
  exact ht

theorem second_addition_noncollision {D T : P} (ht : T ≠ 0)
    (hout : (2 : ℤ) • D + T ≠ 0) : D + T ≠ D ∧ D + T ≠ -D := by
  constructor
  · intro h
    exact ht (add_left_cancel (show D + T = D + 0 by simpa using h))
  · intro h
    apply hout
    have he : (2 : ℤ) • D + T = D + (D + T) := by abel
    rw [he, h, add_neg_cancel]

/-- The second chord division has no new exception once the selected row
and the next primitive prefix are finite. Both facts are derived above. -/
theorem middle_second_noncollision {Q : P} (hq : Q ≠ 0) (scalar : ℤ)
    (hs : ¬Exceptional (scalar : ScalarField)) (num den divisor : ℕ)
    (hn0 : 0 < num) (hd0 : 0 < den) (hn : num < 2 ^ 129) (hd : den < 2 ^ 129)
    (hdiv : 4 ≤ divisor) (hc : Nat.Coprime num den) (hpair : num ≠ 1 ∨ den ≠ 1)
    (hrel : (num : ℤ) • Q + (den : ℤ) • (scalar • Q) = 0) :
    let D := (2 : ℤ) • middleAccumulator num den divisor Q (scalar • Q)
    let T := middleRow num den divisor Q (scalar • Q)
    D + T ≠ D ∧ D + T ≠ -D := by
  apply second_addition_noncollision (middleRow_nonzero hq scalar hs num den divisor)
  have hnz := ladder_prefix_nonzero hq num den divisor hn0 hd0 hn hd hdiv hc hpair hrel
  convert hnz using 1 <;>
    simp only [middleAccumulator, middleRow, zsmul_add,
      sub_zsmul, mul_zsmul] <;> abel

end ZolanaVE.P256.Completeness
