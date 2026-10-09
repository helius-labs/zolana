import VerifiableEncryption.Curve.P256

/-!
Chord and tangent constraints over `Fp` imply Mathlib's group law on
`W.toAffine.Point`. The `_int` variants take the integer congruences the
emulated-field layer produces.
-/

namespace ZolanaVE.P256

open WeierstrassCurve.Affine

theorem two_ne_zero_Fp : (2 : Fp) ≠ 0 := by
  intro h
  have h' : ((2 : ℕ) : Fp) = 0 := by exact_mod_cast h
  rw [ZMod.natCast_zmod_eq_zero_iff_dvd] at h'
  have : p ≤ 2 := Nat.le_of_dvd (by norm_num) h'
  have hp : 2 < p := by decide +kernel
  omega

theorem exists_mkPoint_of_some {x' y' : Fp} (h : W.toAffine.Nonsingular x' y') {x y : Fp}
    (hx : x = x') (hy : y = y') : ∃ hS : OnCurve x y, (Point.some h : P) = mkPoint hS := by
  subst hx
  subst hy
  exact ⟨(equation_iff_onCurve _ _).mp h.1, rfl⟩

theorem cancel_of_mul {d e : Fp} (hd : d ≠ 0) (h : e * d = 0) : e = 0 :=
  (mul_eq_zero.mp h).resolve_right hd

/-- Addition with the slope given as a hinted value `l`. -/
theorem slope_add {xp yp xq yq l xs ys : Fp} (hP : OnCurve xp yp) (hQ : OnCurve xq yq)
    (hx : xp ≠ xq) (hl : l * (xq - xp) = yq - yp) (hxs : xs = l ^ 2 - xp - xq)
    (hys : ys = l * (xp - xs) - yp) :
    ∃ hS : OnCurve xs ys, mkPoint hP + mkPoint hQ = mkPoint hS := by
  have hd : xq - xp ≠ 0 := sub_ne_zero.mpr (Ne.symm hx)
  have hslope : W.toAffine.slope xp xq yp yq = l := by
    rw [slope_of_X_ne hx]
    rw [div_eq_iff (sub_ne_zero.mpr hx)]
    linear_combination hl
  have hX : xs = W.toAffine.addX xp xq (W.toAffine.slope xp xq yp yq) := by
    rw [hslope, addX, W_a₁, W_a₂, hxs]
    ring
  have hY : ys = W.toAffine.addY xp xq yp (W.toAffine.slope xp xq yp yq) := by
    rw [addY, negY_eq, negAddY, ← hX, hslope, hys]
    ring
  unfold mkPoint
  rw [Point.add_of_X_ne hx]
  exact exists_mkPoint_of_some _ hX hY

/-- The chord constraints of `curve.add`: no slope is materialised; the
result is tied to the inputs by two cross-multiplied equations. -/
theorem chord_add {xp yp xq yq xs ys : Fp} (hP : OnCurve xp yp) (hQ : OnCurve xq yq)
    (hx : xp ≠ xq)
    (h1 : (xs + xp + xq) * (xq - xp) ^ 2 - (yq - yp) ^ 2 = 0)
    (h2 : (yq - yp) * (xs - xp) + (ys + yp) * (xq - xp) = 0) :
    ∃ hS : OnCurve xs ys, mkPoint hP + mkPoint hQ = mkPoint hS := by
  have hd : xq - xp ≠ 0 := sub_ne_zero.mpr (Ne.symm hx)
  obtain ⟨l, hl⟩ : ∃ l, l * (xq - xp) = yq - yp := ⟨_, div_mul_cancel₀ _ hd⟩
  refine slope_add hP hQ hx hl ?_ ?_
  · rw [← sub_eq_zero]
    apply cancel_of_mul (pow_ne_zero 2 hd)
    linear_combination h1 - (l * (xq - xp) + (yq - yp)) * hl
  · rw [← sub_eq_zero]
    apply cancel_of_mul hd
    linear_combination h2 + (xs - xp) * hl

/-- The tangent constraint of `curve.tangent`: `2·l·y = 3x² + a` with `a = -3`. -/
theorem tangent_double {x y l xd yd : Fp} (hP : OnCurve x y) (hl : 2 * l * y = 3 * x ^ 2 - 3)
    (hxd : xd = l ^ 2 - 2 * x) (hyd : yd = l * (x - xd) - y) :
    ∃ hD : OnCurve xd yd, 2 • mkPoint hP = mkPoint hD := by
  have hy0 : y ≠ 0 := y_ne_zero_of_onCurve hP
  have hy : y ≠ W.toAffine.negY x y := by
    rw [negY_eq]
    intro h
    apply hy0
    have h2 : (2 : Fp) * y = 0 := by linear_combination h
    exact (mul_eq_zero.mp h2).resolve_left two_ne_zero_Fp
  have h2y : y - W.toAffine.negY x y ≠ 0 := sub_ne_zero.mpr hy
  have hslope : W.toAffine.slope x x y y = l := by
    rw [slope_of_Y_ne rfl hy, div_eq_iff h2y, negY_eq, W_a₁, W_a₂, W_a₄]
    linear_combination -hl
  have hX : xd = W.toAffine.addX x x (W.toAffine.slope x x y y) := by
    rw [hslope, addX, W_a₁, W_a₂, hxd]
    ring
  have hY : yd = W.toAffine.addY x x y (W.toAffine.slope x x y y) := by
    rw [addY, negY_eq, negAddY, ← hX, hslope, hyd]
    ring
  rw [two_nsmul]
  unfold mkPoint
  rw [Point.add_self_of_Y_ne hy]
  exact exists_mkPoint_of_some _ hX hY

/-- `curve.triple`: a tangent, then a return slope `r - l` with
`r·(x - xd) = 2y`. A collision `x = xd` would force `y = 0`, so the ratio
constraint alone rules it out. -/
theorem triple {x y l xd r x3 y3 : Fp} (hP : OnCurve x y) (hl : 2 * l * y = 3 * x ^ 2 - 3)
    (hxd : xd = l ^ 2 - 2 * x) (hr : r * (x - xd) = 2 * y)
    (hx3 : x3 = (r - l) ^ 2 - x - xd) (hy3 : y3 = (r - l) * (x - x3) - y) :
    ∃ hT : OnCurve x3 y3, 3 • mkPoint hP = mkPoint hT := by
  obtain ⟨hD, hDeq⟩ := tangent_double hP hl hxd rfl
  have hx : x ≠ xd := by
    intro h
    apply y_ne_zero_of_onCurve hP
    have h2 : (2 : Fp) * y = 0 := by rw [← hr, h, sub_self, mul_zero]
    exact (mul_eq_zero.mp h2).resolve_left two_ne_zero_Fp
  have hd : xd - x ≠ 0 := sub_ne_zero.mpr (Ne.symm hx)
  obtain ⟨hT, hTeq⟩ := slope_add (xs := x3) (ys := y3) hP hD hx (l := r - l) (by
    linear_combination (-1 : Fp) * hr) hx3 hy3
  refine ⟨hT, ?_⟩
  rw [show (3 : ℕ) = 1 + 2 from rfl, add_nsmul, one_nsmul, hDeq, hTeq]

/-- `curve.completeAdd` after the boolean and distinct-x guards are
discharged: `s` is the claimed same-x flag. -/
theorem complete_add {xp yp xq yq l s xs ys : Fp} (hP : OnCurve xp yp) (hQ : OnCurve xq yq)
    (hs : s = 0 ∨ s = 1) (hdistinct : s = 0 → xp ≠ xq)
    (hsx : s * (xq - xp) = 0) (hsy : s * (yq - yp) = 0)
    (hl : l * (xq - xp) + s * (2 * l * yp - 3 * xp ^ 2 + 3) - (yq - yp) = 0)
    (hxs : xs = l ^ 2 - xp - xq) (hys : ys = l * (xp - xs) - yp) :
    ∃ hS : OnCurve xs ys, mkPoint hP + mkPoint hQ = mkPoint hS := by
  rcases hs with rfl | rfl
  · exact slope_add hP hQ (hdistinct rfl) (by linear_combination hl) hxs hys
  · have hxq : xq = xp := by linear_combination hsx
    have hyq : yq = yp := by linear_combination hsy
    subst hxq
    subst hyq
    obtain ⟨hD, hDeq⟩ := tangent_double (xd := xs) (yd := ys) hP (l := l)
      (by linear_combination hl) (by rw [hxs]; ring) hys
    exact ⟨hD, by rw [← two_nsmul]; exact hDeq⟩

theorem cast_zero_of_modEq {a : ℤ} (h : a ≡ 0 [ZMOD p]) : ((a : ℤ) : Fp) = 0 := by
  have := (ZMod.intCast_eq_intCast_iff a 0 p).mpr h
  simpa using this

theorem cast_eq_of_modEq {a c : ℤ} (h : a ≡ c [ZMOD p]) : ((a : ℤ) : Fp) = (c : Fp) :=
  (ZMod.intCast_eq_intCast_iff a c p).mpr h

theorem chord_add_int {xp yp xq yq xs ys : ℤ} (hP : OnCurve (xp : Fp) (yp : Fp))
    (hQ : OnCurve (xq : Fp) (yq : Fp)) (hx : (xp : Fp) ≠ (xq : Fp))
    (h1 : (xs + xp + xq) * (xq - xp) ^ 2 - (yq - yp) ^ 2 ≡ 0 [ZMOD p])
    (h2 : (yq - yp) * (xs - xp) + (ys + yp) * (xq - xp) ≡ 0 [ZMOD p]) :
    ∃ hS : OnCurve (xs : Fp) (ys : Fp), mkPoint hP + mkPoint hQ = mkPoint hS := by
  have h1' := cast_zero_of_modEq h1
  have h2' := cast_zero_of_modEq h2
  push_cast at h1' h2'
  exact chord_add hP hQ hx h1' h2'

theorem slope_add_int {xp yp xq yq l xs ys : ℤ} (hP : OnCurve (xp : Fp) (yp : Fp))
    (hQ : OnCurve (xq : Fp) (yq : Fp)) (hx : (xp : Fp) ≠ (xq : Fp))
    (hl : l * (xq - xp) ≡ yq - yp [ZMOD p]) (hxs : xs ≡ l ^ 2 - xp - xq [ZMOD p])
    (hys : ys ≡ l * (xp - xs) - yp [ZMOD p]) :
    ∃ hS : OnCurve (xs : Fp) (ys : Fp), mkPoint hP + mkPoint hQ = mkPoint hS := by
  have hl' := cast_eq_of_modEq hl
  have hxs' := cast_eq_of_modEq hxs
  have hys' := cast_eq_of_modEq hys
  push_cast at hl' hxs' hys'
  exact slope_add hP hQ hx hl' hxs' hys'

theorem tangent_double_int {x y l xd yd : ℤ} (hP : OnCurve (x : Fp) (y : Fp))
    (hl : 2 * l * y ≡ 3 * x ^ 2 - 3 [ZMOD p]) (hxd : xd ≡ l ^ 2 - 2 * x [ZMOD p])
    (hyd : yd ≡ l * (x - xd) - y [ZMOD p]) :
    ∃ hD : OnCurve (xd : Fp) (yd : Fp), 2 • mkPoint hP = mkPoint hD := by
  have hl' := cast_eq_of_modEq hl
  have hxd' := cast_eq_of_modEq hxd
  have hyd' := cast_eq_of_modEq hyd
  push_cast at hl' hxd' hyd'
  exact tangent_double hP hl' hxd' hyd'

end ZolanaVE.P256
