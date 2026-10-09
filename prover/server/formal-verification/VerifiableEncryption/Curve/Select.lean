import VerifiableEncryption.Curve.TripleStep

/-!
`Field.Select`, constants, and re-bounded elements.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-- Bounds `Field.Select` attaches: limbwise and value-wise min/max. -/
def selBnd (a b : ElemC) : ElemC :=
  ⟨List.zipWith min a.lo b.lo, List.zipWith max a.hi b.hi, min a.vlo b.vlo, max a.vhi b.vhi⟩

theorem getD_zipWith {f : ℤ → ℤ → ℤ} {l m : List ℤ} (hl : l.length = 8) (hm : m.length = 8) (i : Fin 8) :
    (List.zipWith f l m).getD i 0 = f (l.getD i 0) (m.getD i 0) := by
  rw [List.getD_eq_getElem _ _ (by simp [hl, hm]), List.getD_eq_getElem _ _ (by rw [hl]; exact i.2),
    List.getD_eq_getElem _ _ (by rw [hm]; exact i.2)]
  simp

theorem _root_.ZolanaVE.Field.ElemVal.lo_len (e : ElemVal 8) : e.bnd.lo.length = 8 := by simp [ElemVal.bnd]
theorem _root_.ZolanaVE.Field.ElemVal.hi_len (e : ElemVal 8) : e.bnd.hi.length = 8 := by simp [ElemVal.bnd]

/-- An element's integers fit the select bounds of its own and another element's bounds. -/
theorem fits_selBnd_left (A : ElemVal 8) (c : ElemC) (hlo : c.lo.length = 8) (hhi : c.hi.length = 8) :
    Fits (fun i => A.ints.get i) (selBnd A.bnd c) := by
  refine ⟨by simp [selBnd, ElemVal.bnd, hlo], by simp [selBnd, ElemVal.bnd, hhi], fun i => ?_, ?_, ?_⟩
  · simp only [selBnd]
    rw [getD_zipWith A.lo_len hlo, getD_zipWith A.hi_len hhi]
    exact ⟨(min_le_left _ _).trans (A.lo_le i), (A.le_hi i).trans (le_max_left _ _)⟩
  · rw [← A.value_eq]; exact (min_le_left _ _).trans A.vlo_le
  · rw [← A.value_eq]; exact A.le_vhi.trans (le_max_left _ _)

theorem fits_selBnd_right (c : ElemC) (B : ElemVal 8) (hlo : c.lo.length = 8) (hhi : c.hi.length = 8) :
    Fits (fun i => B.ints.get i) (selBnd c B.bnd) := by
  refine ⟨by simp [selBnd, ElemVal.bnd, hlo], by simp [selBnd, ElemVal.bnd, hhi], fun i => ?_, ?_, ?_⟩
  · simp only [selBnd]
    rw [getD_zipWith hlo B.lo_len, getD_zipWith hhi B.hi_len]
    exact ⟨(min_le_right _ _).trans (B.lo_le i), (B.le_hi i).trans (le_max_right _ _)⟩
  · rw [← B.value_eq]; exact (min_le_right _ _).trans B.vlo_le
  · rw [← B.value_eq]; exact B.le_vhi.trans (le_max_right _ _)

/-- `Select(b, A, B)` for a known boolean `b`. -/
def selElem (b : Bool) (A B : ElemVal 8) : ElemVal 8 :=
  if b then mkElem _ _ (fits_selBnd_left A B.bnd B.lo_len B.hi_len)
  else mkElem _ _ (fits_selBnd_right A.bnd B A.lo_len A.hi_len)

theorem selElem_bnd (b : Bool) (A B : ElemVal 8) : (selElem b A B).bnd = selBnd A.bnd B.bnd := by
  cases b <;> rfl

theorem selElem_value (b : Bool) (A B : ElemVal 8) :
    (selElem b A B).value = if b then A.value else B.value := by
  cases b <;> simp [selElem, A.value_eq, B.value_eq]

theorem selElem_limb (b : Bool) (A B : ElemVal 8) (i : Fin 8) :
    (selElem b A B).limbs.get i = (B.limbs.get i) - ((if b then 1 else 0 : F)) * (B.limbs.get i - A.limbs.get i) := by
  cases b <;> simp [selElem, ElemVal.limb_eq]

/-- A boolean native value is the cast of a `Bool`. -/
theorem bool_of_is_bool {c : F} (h : GatesDef.is_bool c) : ∃ b : Bool, c = if b then 1 else 0 := by
  unfold GatesDef.is_bool at h
  rcases mul_eq_zero.mp h with h | h
  · exact ⟨true, by simp; linear_combination -h⟩
  · exact ⟨false, by simp [h]⟩

/-- The constant element `Field.Const` with the given limbs. -/
def constC (x : Fin 8 → ℤ) : ElemC := ⟨List.ofFn x, List.ofFn x, rec8 x, rec8 x⟩

theorem const_fits (x : Fin 8 → ℤ) : Fits x (constC x) := by
  refine ⟨by simp [constC], by simp [constC], fun i => ?_, le_rfl, le_rfl⟩
  simp only [constC]
  rw [List.getD_eq_getElem _ _ (by simp), List.getElem_ofFn]
  exact ⟨le_rfl, le_rfl⟩

def constElem (x : Fin 8 → ℤ) : ElemVal 8 := mkElem x (constC x) (const_fits x)

theorem constElem_value (x : Fin 8 → ℤ) : (constElem x).value = rec8 x := by
  rw [constElem, mkElem_value]

/-- Re-attach wider bounds to an element. -/
def rebound (A : ElemVal 8) (c : ElemC) (h : Fits (fun i => A.ints.get i) c) : ElemVal 8 := mkElem _ c h

theorem rebound_value (A : ElemVal 8) (c : ElemC) (h : Fits (fun i => A.ints.get i) c) :
    (rebound A c h).value = A.value := by
  rw [rebound, mkElem_value, A.value_eq]

theorem rebound_limbs (A : ElemVal 8) (c : ElemC) (h : Fits (fun i => A.ints.get i) c) :
    (rebound A c h).limbs = A.limbs := by
  apply List.Vector.ext
  intro i
  simp [rebound, ElemVal.limb_eq]

theorem reduced_lohi {e : ElemVal 8} (h : e.bnd = reducedC) (i : Fin 8) :
    e.lo.get i = 0 ∧ e.hi.get i = 2 ^ 32 - 1 := by
  simp only [ElemVal.bnd, reducedC, uniC, ElemC.mk.injEq] at h
  obtain ⟨h1, h2, -, -⟩ := h
  constructor
  · rw [List.Vector.get_eq_get_toList]; simp [h1]; fin_cases i <;> rfl
  · rw [List.Vector.get_eq_get_toList]; simp [h2]; fin_cases i <;> rfl

end ZolanaVE.P256
