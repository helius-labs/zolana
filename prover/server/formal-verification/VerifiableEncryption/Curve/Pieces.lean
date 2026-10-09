import VerifiableEncryption.Curve.Elem

/-!
Hinted reduced elements: each limb is composed from range-checked pieces
of 11, 11 and 10 bits (`Field.fromPieces` with the lookup layout).
-/

namespace ZolanaVE.Field

theorem getD_rep8 (v : ℤ) (i : Fin 8) : (List.replicate 8 v).getD i 0 = v := by
  fin_cases i <;> rfl

/-- Bounds that are the same on every limb. -/
def uniC (lo hi vlo vhi : ℤ) : ElemC := ⟨List.replicate 8 lo, List.replicate 8 hi, vlo, vhi⟩

theorem fits_uni {x : Fin 8 → ℤ} {lo hi vlo vhi : ℤ} (h : ∀ i, lo ≤ x i ∧ x i ≤ hi)
    (hv : vlo ≤ rec8 x ∧ rec8 x ≤ vhi) : Fits x (uniC lo hi vlo vhi) := by
  refine ⟨by simp [uniC], by simp [uniC], fun i => ?_, hv.1, hv.2⟩
  simp only [uniC]
  rw [getD_rep8, getD_rep8]
  exact h i

theorem uni_limb {e : ElemVal 8} {lo hi vlo vhi : ℤ} (h : e.bnd = uniC lo hi vlo vhi) (i : Fin 8) :
    lo ≤ e.ints.get i ∧ e.ints.get i ≤ hi := by
  have := (e.fits_of_bnd h).1 i
  simp only [uniC] at this
  rwa [getD_rep8, getD_rep8] at this

theorem uni_value {e : ElemVal 8} {lo hi vlo vhi : ℤ} (h : e.bnd = uniC lo hi vlo vhi) :
    vlo ≤ e.value ∧ e.value ≤ vhi :=
  (e.fits_of_bnd h).2

/-- The bounds `Field.Reduced` attaches: 32-bit limbs, value below `2^256`. -/
def reducedC : ElemC := uniC 0 (2 ^ 32 - 1) 0 (2 ^ 256 - 1)

/-- `Sub` of two reduced elements. -/
def subRedC : ElemC := uniC (-(2 ^ 32 - 1)) (2 ^ 32 - 1) (-(2 ^ 256 - 1)) (2 ^ 256 - 1)

theorem rec8_sub (a b : Fin 8 → ℤ) : rec8 (fun i => a i - b i) = rec8 a - rec8 b := by
  unfold rec8; ring

theorem rec8_add (a b : Fin 8 → ℤ) : rec8 (fun i => a i + b i) = rec8 a + rec8 b := by
  unfold rec8; ring

theorem rec8_smul (c : ℤ) (a : Fin 8 → ℤ) : rec8 (fun i => c * a i) = c * rec8 a := by
  unfold rec8; ring

theorem sub_red_fits {A B : ElemVal 8} (hA : A.bnd = reducedC) (hB : B.bnd = reducedC) :
    Fits (fun i => A.ints.get i - B.ints.get i) subRedC := by
  apply fits_uni
  · intro i
    have := uni_limb hA i; have := uni_limb hB i
    constructor <;> linarith
  · rw [rec8_sub, ← A.value_eq, ← B.value_eq]
    have := uni_value hA; have := uni_value hB
    constructor <;> linarith

theorem vget_getD {n : ℕ} (g : List.Vector F n) (i : Fin n) : g.get i = g.toList.getD i.val 0 := by
  rw [List.Vector.get_eq_get_toList, List.getD_eq_getElem _ _ (by simp)]
  rfl

theorem rc_getD {n b : ℕ} {g : List.Vector F n} {i : Fin n} (h : RangeCheck b (g.get i)) :
    RangeCheck b (g.toList.getD i.val 0) := by
  rwa [vget_getD] at h

/-- The integer a limb composed from three hinted pieces stands for. -/
def pieceInt {n : ℕ} (g : List.Vector F n) (o : ℕ) : ℤ :=
  ((g.toList.getD o 0).val + 2048 * (g.toList.getD (o + 1) 0).val +
    4194304 * (g.toList.getD (o + 2) 0).val : ℕ)

/-- Range checks of the three pieces of the limb at offset `o`. -/
def PieceRC {n : ℕ} (g : List.Vector F n) (o : ℕ) : Prop :=
  RangeCheck 11 (g.toList.getD o 0) ∧ RangeCheck 11 (g.toList.getD (o + 1) 0) ∧
    RangeCheck 10 (g.toList.getD (o + 2) 0)

theorem pieceInt_bounds (hl : LookupSound RangeCheck 11) {n : ℕ} {g : List.Vector F n} {o : ℕ}
    (h : PieceRC g o) : 0 ≤ pieceInt g o ∧ pieceInt g o ≤ 2 ^ 32 - 1 := by
  have h0 := hl 11 _ (by norm_num) (by norm_num) h.1
  have h1 := hl 11 _ (by norm_num) (by norm_num) h.2.1
  have h2 := hl 10 _ (by norm_num) (by norm_num) h.2.2
  unfold pieceInt
  constructor
  · positivity
  · have : (g.toList.getD o 0).val + 2048 * (g.toList.getD (o + 1) 0).val +
        4194304 * (g.toList.getD (o + 2) 0).val ≤ 4294967295 := by omega
    have h' : (((g.toList.getD o 0).val + 2048 * (g.toList.getD (o + 1) 0).val +
        4194304 * (g.toList.getD (o + 2) 0).val : ℕ) : ℤ) ≤ 4294967295 := by exact_mod_cast this
    exact h'.trans (by norm_num)

theorem pieceInt_cast {n : ℕ} (g : List.Vector F n) (o : ℕ) :
    ((pieceInt g o : ℤ) : F) =
      0 + g.toList.getD o 0 * 1 + g.toList.getD (o + 1) 0 * 2048 + g.toList.getD (o + 2) 0 * 4194304 := by
  unfold pieceInt
  push_cast
  simp only [ZMod.natCast_val, ZMod.cast_id', id]
  ring

theorem rec8_reduced_bounds {x : Fin 8 → ℤ} (h : ∀ i, 0 ≤ x i ∧ x i ≤ 2 ^ 32 - 1) :
    0 ≤ rec8 x ∧ rec8 x ≤ 2 ^ 256 - 1 := by
  have h0 := h 0; have h1 := h 1; have h2 := h 2; have h3 := h 3
  have h4 := h 4; have h5 := h 5; have h6 := h 6; have h7 := h 7
  unfold rec8
  norm_num at *
  constructor <;> linarith

/-- A hinted element of eight piece-composed limbs starting at offset `o`. -/
theorem pieces_fits (hl : LookupSound RangeCheck 11) {n : ℕ} {g : List.Vector F n} {o : ℕ}
    (h : ∀ i : Fin 8, PieceRC g (o + 3 * i.val)) :
    Fits (fun i => pieceInt g (o + 3 * i.val)) reducedC := by
  have hb : ∀ i : Fin 8, 0 ≤ pieceInt g (o + 3 * i.val) ∧ pieceInt g (o + 3 * i.val) ≤ 2 ^ 32 - 1 :=
    fun i => pieceInt_bounds hl (h i)
  refine ⟨rfl, rfl, fun i => ?_, ?_, ?_⟩
  · have := hb i
    fin_cases i <;> simpa [reducedC] using this
  · simpa [reducedC] using (rec8_reduced_bounds hb).1
  · simpa [reducedC] using (rec8_reduced_bounds hb).2

theorem add_red_fits {A B : ElemVal 8} (hA : A.bnd = reducedC) (hB : B.bnd = reducedC) :
    Fits (fun i => A.ints.get i + B.ints.get i) (uniC 0 (2 * (2 ^ 32 - 1)) 0 (2 * (2 ^ 256 - 1))) := by
  apply fits_uni
  · intro i
    have := uni_limb hA i; have := uni_limb hB i
    constructor <;> linarith
  · rw [rec8_add, ← A.value_eq, ← B.value_eq]
    have := uni_value hA; have := uni_value hB
    constructor <;> linarith

theorem add3_red_fits {A B C : ElemVal 8} (hA : A.bnd = reducedC) (hB : B.bnd = reducedC)
    (hC : C.bnd = reducedC) :
    Fits (fun i => A.ints.get i + B.ints.get i + C.ints.get i)
      (uniC 0 (3 * (2 ^ 32 - 1)) 0 (3 * (2 ^ 256 - 1))) := by
  apply fits_uni
  · intro i
    have := uni_limb hA i; have := uni_limb hB i; have := uni_limb hC i
    constructor <;> linarith
  · rw [rec8_add, rec8_add, ← A.value_eq, ← B.value_eq, ← C.value_eq]
    have := uni_value hA; have := uni_value hB; have := uni_value hC
    constructor <;> linarith

theorem getElem_eq_getD0 {α : Type*} [Zero α] (l : List α) (i : ℕ) (h : i < l.length) :
    l[i] = l.getD i 0 :=
  (List.getD_eq_getElem l 0 h).symm

theorem lazy_bnd {c : LazyParams} {e : ElemVal 8} (h1 : e.lo.toList = c.outLo) (h2 : e.hi.toList = c.outHi)
    (h3 : e.vlo = c.outVlo) (h4 : e.vhi = c.outVhi) : e.bnd = ⟨c.outLo, c.outHi, c.outVlo, c.outVhi⟩ := by
  simp [ElemVal.bnd, h1, h2, h3, h4]

theorem eval_bnd {c : PlainCheckParams} {e : ElemVal 8}
    (h1 : e.lo.toList = List.replicate limbCount 0)
    (h2 : e.hi.toList = c.resultWidths.map (fun w => (2 : ℤ) ^ w - 1))
    (h3 : e.vlo = 0) (h4 : e.vhi = recompose (c.resultWidths.map fun w => (2 : ℤ) ^ w - 1))
    (hw : c.resultWidths = List.replicate 8 32) : e.bnd = reducedC := by
  simp only [ElemVal.bnd, h1, h2, h3, h4, hw, reducedC, uniC, limbCount]
  rfl

@[simp] theorem mkElem_int (x : Fin 8 → ℤ) (c : ElemC) (h : Fits x c) (i : Fin 8) :
    (mkElem x c h).ints.get i = x i := by
  simp [mkElem]

end ZolanaVE.Field
