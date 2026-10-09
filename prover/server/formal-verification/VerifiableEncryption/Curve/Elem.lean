import VerifiableEncryption.Field.InstanceKit

/-!
Eight-limb elements with prescribed bounds.

A check certificate fixes the exact bounds of every input element. The curve
proofs build each input as `mkElem x c _`: integer limbs `x` placed inside the
certified bounds `c`, so `ElemsMatch` holds by construction and only the
interval facts about `x` remain to be shown.
-/

namespace ZolanaVE.Field

theorem vec8_toList {α : Type*} (v : List.Vector α 8) :
    v.toList = [v.get 0, v.get 1, v.get 2, v.get 3, v.get 4, v.get 5, v.get 6, v.get 7] := by
  obtain ⟨l, hl⟩ := v
  match l, hl with
  | [a0, a1, a2, a3, a4, a5, a6, a7], _ => rfl

/-- `recompose` on eight limbs, with the powers of the base written out. -/
def rec8 (x : Fin 8 → ℤ) : ℤ :=
  x 0 + 2 ^ 32 * x 1 + 2 ^ 64 * x 2 + 2 ^ 96 * x 3 + 2 ^ 128 * x 4 + 2 ^ 160 * x 5 +
    2 ^ 192 * x 6 + 2 ^ 224 * x 7

theorem recompose_eight (a0 a1 a2 a3 a4 a5 a6 a7 : ℤ) :
    recompose [a0, a1, a2, a3, a4, a5, a6, a7] = rec8 ![a0, a1, a2, a3, a4, a5, a6, a7] := by
  simp only [recompose, evalAt_cons, evalAt_nil, limbBase, rec8]
  show _ = a0 + 2 ^ 32 * a1 + 2 ^ 64 * a2 + 2 ^ 96 * a3 + 2 ^ 128 * a4 + 2 ^ 160 * a5 +
    2 ^ 192 * a6 + 2 ^ 224 * a7
  ring

theorem recompose_vec (v : List.Vector ℤ 8) : recompose v.toList = rec8 (fun i => v.get i) := by
  rw [vec8_toList, recompose_eight]
  simp only [rec8]
  rfl

theorem ElemVal.value_eq (e : ElemVal 8) : e.value = rec8 (fun i => e.ints.get i) :=
  recompose_vec e.ints

/-- Bounds of an element, in the certificate's format. -/
def ElemVal.bnd {w : ℕ} (e : ElemVal w) : ElemC := ⟨e.lo.toList, e.hi.toList, e.vlo, e.vhi⟩

theorem elemsMatch_of {es : List (Σ w, ElemVal w)} {cs : List ElemC}
    (h : es.map (fun e => e.2.bnd) = cs) : ElemsMatch es cs := by
  subst h
  induction es with
  | nil => exact List.Forall₂.nil
  | cons e es ih => exact List.Forall₂.cons ⟨rfl, rfl, rfl, rfl⟩ ih

/-- Integer limbs `x` lie in the bounds `c`. -/
def Fits (x : Fin 8 → ℤ) (c : ElemC) : Prop :=
  c.lo.length = 8 ∧ c.hi.length = 8 ∧
  (∀ i : Fin 8, c.lo.getD i 0 ≤ x i ∧ x i ≤ c.hi.getD i 0) ∧
  c.vlo ≤ rec8 x ∧ rec8 x ≤ c.vhi

/-- The element with integer limbs `x` and bounds `c`. -/
def mkElem (x : Fin 8 → ℤ) (c : ElemC) (h : Fits x c) : ElemVal 8 where
  limbs := List.Vector.ofFn fun i => (x i : F)
  ints := List.Vector.ofFn x
  lo := ⟨c.lo, h.1⟩
  hi := ⟨c.hi, h.2.1⟩
  vlo := c.vlo
  vhi := c.vhi
  h_cast := by intro i; simp
  h_lo := by
    intro i
    have := (h.2.2.1 i).1
    rw [List.getD_eq_getElem _ _ (by rw [h.1]; exact i.2)] at this
    rw [List.Vector.get_ofFn]
    exact this
  h_hi := by
    intro i
    have := (h.2.2.1 i).2
    rw [List.getD_eq_getElem _ _ (by rw [h.2.1]; exact i.2)] at this
    rw [List.Vector.get_ofFn]
    exact this
  h_vlo := by
    rw [recompose_vec]
    simpa using h.2.2.2.1
  h_vhi := by
    rw [recompose_vec]
    simpa using h.2.2.2.2

@[simp] theorem mkElem_bnd (x : Fin 8 → ℤ) (c : ElemC) (h : Fits x c) : (mkElem x c h).bnd = c := rfl

@[simp] theorem mkElem_limb (x : Fin 8 → ℤ) (c : ElemC) (h : Fits x c) (i : Fin 8) :
    (mkElem x c h).limbs.get i = (x i : F) := by
  simp [mkElem]

theorem mkElem_limbs (x : Fin 8 → ℤ) (c : ElemC) (h : Fits x c) :
    (mkElem x c h).limbs.toList = [(x 0 : F), x 1, x 2, x 3, x 4, x 5, x 6, x 7] := by
  rw [vec8_toList]
  simp only [mkElem_limb]

@[simp] theorem mkElem_value (x : Fin 8 → ℤ) (c : ElemC) (h : Fits x c) :
    (mkElem x c h).value = rec8 x := by
  rw [ElemVal.value_eq]
  simp [mkElem]

theorem ElemVal.limb_eq (e : ElemVal 8) (i : Fin 8) : e.limbs.get i = (e.ints.get i : F) := e.h_cast i

theorem ElemVal.lo_le (e : ElemVal 8) (i : Fin 8) : e.lo.toList.getD i 0 ≤ e.ints.get i := by
  have := e.h_lo i
  rwa [List.Vector.get_eq_get_toList, List.get_eq_getElem,
    ← List.getD_eq_getElem _ 0 (by simp)] at this

theorem ElemVal.le_hi (e : ElemVal 8) (i : Fin 8) : e.ints.get i ≤ e.hi.toList.getD i 0 := by
  have := e.h_hi i
  rwa [List.Vector.get_eq_get_toList (v := e.hi), List.get_eq_getElem,
    ← List.getD_eq_getElem _ 0 (by simp)] at this

theorem ElemVal.vlo_le (e : ElemVal 8) : e.vlo ≤ e.value := e.h_vlo

theorem ElemVal.le_vhi (e : ElemVal 8) : e.value ≤ e.vhi := e.h_vhi

/-- Interval facts about an element whose bounds are known to be `c`. -/
theorem ElemVal.fits_of_bnd (e : ElemVal 8) {c : ElemC} (h : e.bnd = c) :
    (∀ i : Fin 8, c.lo.getD i 0 ≤ e.ints.get i ∧ e.ints.get i ≤ c.hi.getD i 0) ∧
      c.vlo ≤ e.value ∧ e.value ≤ c.vhi := by
  subst h
  exact ⟨fun i => ⟨e.lo_le i, e.le_hi i⟩, e.vlo_le, e.le_vhi⟩

/-! ### Five-limb elements (`scalarFromBits` of 129 bits) -/

theorem vec5_toList {α : Type*} (v : List.Vector α 5) :
    v.toList = [v.get 0, v.get 1, v.get 2, v.get 3, v.get 4] := by
  obtain ⟨l, hl⟩ := v
  match l, hl with
  | [a0, a1, a2, a3, a4], _ => rfl

def rec5 (x : Fin 5 → ℤ) : ℤ := x 0 + 2 ^ 32 * x 1 + 2 ^ 64 * x 2 + 2 ^ 96 * x 3 + 2 ^ 128 * x 4

theorem recompose_vec5 (v : List.Vector ℤ 5) : recompose v.toList = rec5 (fun i => v.get i) := by
  rw [vec5_toList]
  simp only [recompose, evalAt_cons, evalAt_nil, limbBase, rec5]
  ring

def Fits5 (x : Fin 5 → ℤ) (c : ElemC) : Prop :=
  c.lo.length = 5 ∧ c.hi.length = 5 ∧
  (∀ i : Fin 5, c.lo.getD i 0 ≤ x i ∧ x i ≤ c.hi.getD i 0) ∧
  c.vlo ≤ rec5 x ∧ rec5 x ≤ c.vhi

def mkElem5 (x : Fin 5 → ℤ) (c : ElemC) (h : Fits5 x c) : ElemVal 5 where
  limbs := List.Vector.ofFn fun i => (x i : F)
  ints := List.Vector.ofFn x
  lo := ⟨c.lo, h.1⟩
  hi := ⟨c.hi, h.2.1⟩
  vlo := c.vlo
  vhi := c.vhi
  h_cast := by intro i; simp
  h_lo := by
    intro i
    have := (h.2.2.1 i).1
    rw [List.getD_eq_getElem _ _ (by rw [h.1]; exact i.2)] at this
    rw [List.Vector.get_ofFn]
    exact this
  h_hi := by
    intro i
    have := (h.2.2.1 i).2
    rw [List.getD_eq_getElem _ _ (by rw [h.2.1]; exact i.2)] at this
    rw [List.Vector.get_ofFn]
    exact this
  h_vlo := by
    rw [recompose_vec5]
    simpa using h.2.2.2.1
  h_vhi := by
    rw [recompose_vec5]
    simpa using h.2.2.2.2

@[simp] theorem mkElem5_limb (x : Fin 5 → ℤ) (c : ElemC) (h : Fits5 x c) (i : Fin 5) :
    (mkElem5 x c h).limbs.get i = (x i : F) := by
  simp [mkElem5]

theorem mkElem5_limbs (x : Fin 5 → ℤ) (c : ElemC) (h : Fits5 x c) :
    (mkElem5 x c h).limbs.toList = [(x 0 : F), x 1, x 2, x 3, x 4] := by
  rw [vec5_toList]
  simp only [mkElem5_limb]

theorem mkElem5_value (x : Fin 5 → ℤ) (c : ElemC) (h : Fits5 x c) :
    (mkElem5 x c h).value = rec5 x := by
  rw [ElemVal.value, recompose_vec5]
  simp [mkElem5]

def ElemVal.bnd5 (e : ElemVal 5) : ElemC := ⟨e.lo.toList, e.hi.toList, e.vlo, e.vhi⟩

theorem elemsMatch_cons {e : Σ w, ElemVal w} {es : List (Σ w, ElemVal w)} {c : ElemC} {cs : List ElemC}
    (h1 : e.2.lo.toList = c.lo ∧ e.2.hi.toList = c.hi ∧ e.2.vlo = c.vlo ∧ e.2.vhi = c.vhi)
    (h2 : ElemsMatch es cs) : ElemsMatch (e :: es) (c :: cs) :=
  List.Forall₂.cons h1 h2

end ZolanaVE.Field
