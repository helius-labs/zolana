import VerifiableEncryption.Curve.Pieces

/-!
`Field.Lin` bounds.

`linC` recomputes the limb and value bounds `Field.Lin` attaches to
`∑ cⱼ·eⱼ` (`field.go`): each scaled interval is `[c·lo, c·hi]`, swapped for a
negative coefficient, and the intervals add. A certificate's element is
matched by `rfl` against `linC` of its inputs' bounds.
-/

namespace ZolanaVE.Field

def sLo (c lo hi : ℤ) : ℤ := if 0 ≤ c then c * lo else c * hi
def sHi (c lo hi : ℤ) : ℤ := if 0 ≤ c then c * hi else c * lo

theorem scaled_bounds {c lo hi x : ℤ} (h1 : lo ≤ x) (h2 : x ≤ hi) :
    sLo c lo hi ≤ c * x ∧ c * x ≤ sHi c lo hi := by
  unfold sLo sHi
  split_ifs with hc
  · exact ⟨mul_le_mul_of_nonneg_left h1 hc, mul_le_mul_of_nonneg_left h2 hc⟩
  · push_neg at hc
    exact ⟨mul_le_mul_of_nonpos_left h2 hc.le, mul_le_mul_of_nonpos_left h1 hc.le⟩

/-- Bounds of `∑ cⱼ·eⱼ` from the bounds of the `eⱼ`. -/
def linC (ts : List (ℤ × ElemC)) : ElemC where
  lo := (List.range 8).map fun i => (ts.map fun t => sLo t.1 (t.2.lo.getD i 0) (t.2.hi.getD i 0)).sum
  hi := (List.range 8).map fun i => (ts.map fun t => sHi t.1 (t.2.lo.getD i 0) (t.2.hi.getD i 0)).sum
  vlo := (ts.map fun t => sLo t.1 t.2.vlo t.2.vhi).sum
  vhi := (ts.map fun t => sHi t.1 t.2.vlo t.2.vhi).sum

/-- Integer limbs of `∑ cⱼ·eⱼ`. -/
def linX (ts : List (ℤ × ElemVal 8)) (i : Fin 8) : ℤ := (ts.map fun t => t.1 * t.2.ints.get i).sum

theorem rec8_linX (ts : List (ℤ × ElemVal 8)) :
    rec8 (linX ts) = (ts.map fun t => t.1 * t.2.value).sum := by
  induction ts with
  | nil => simp [linX, rec8]
  | cons t ts ih =>
    simp only [List.map_cons, List.sum_cons]
    rw [← ih, t.2.value_eq]
    simp only [linX, List.map_cons, List.sum_cons, rec8]
    ring

theorem getD_range_map (f : ℕ → ℤ) (i : Fin 8) : ((List.range 8).map f).getD i 0 = f i := by
  rw [List.getD_eq_getElem _ _ (by simp)]
  simp

theorem lin_fits (ts : List (ℤ × ElemVal 8)) :
    Fits (linX ts) (linC (ts.map fun t => (t.1, t.2.bnd))) := by
  refine ⟨by simp [linC], by simp [linC], fun i => ?_, ?_, ?_⟩
  · simp only [linC, getD_range_map, List.map_map]
    induction ts with
    | nil => simp [linX]
    | cons t ts ih =>
      simp only [List.map_cons, List.sum_cons, linX, Function.comp] at ih ⊢
      have hb := scaled_bounds (c := t.1) (t.2.lo_le i) (t.2.le_hi i)
      simp only [ElemVal.bnd] at ih ⊢
      constructor <;> linarith [ih.1, ih.2, hb.1, hb.2]
  · rw [rec8_linX]
    simp only [linC, List.map_map]
    induction ts with
    | nil => simp
    | cons t ts ih =>
      simp only [List.map_cons, List.sum_cons, Function.comp] at ih ⊢
      have hb := scaled_bounds (c := t.1) t.2.vlo_le t.2.le_vhi
      simp only [ElemVal.bnd] at ih ⊢
      linarith
  · rw [rec8_linX]
    simp only [linC, List.map_map]
    induction ts with
    | nil => simp
    | cons t ts ih =>
      simp only [List.map_cons, List.sum_cons, Function.comp] at ih ⊢
      have hb := scaled_bounds (c := t.1) t.2.vlo_le t.2.le_vhi
      simp only [ElemVal.bnd] at ih ⊢
      linarith

/-- The element `∑ cⱼ·eⱼ`, with exactly the bounds `Field.Lin` computes. -/
def linElem (ts : List (ℤ × ElemVal 8)) : ElemVal 8 :=
  mkElem (linX ts) _ (lin_fits ts)

theorem linElem_bnd (ts : List (ℤ × ElemVal 8)) :
    (linElem ts).bnd = linC (ts.map fun t => (t.1, t.2.bnd)) := rfl

theorem linElem_value (ts : List (ℤ × ElemVal 8)) :
    (linElem ts).value = (ts.map fun t => t.1 * t.2.value).sum := by
  rw [linElem, mkElem_value, rec8_linX]

end ZolanaVE.Field
