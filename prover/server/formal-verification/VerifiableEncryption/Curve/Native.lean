import VerifiableEncryption.Curve.LinElem
import VerifiableEncryption.Curve.Guards
import VerifiableEncryption.Circuit.Curve

/-!
Native-field gadgets on emulated elements: `curve.nativeValue`, the
distinct-slope guard, and balanced hinted elements (`Field.HintBalanced`).
-/

namespace ZolanaVE.P256

open ZolanaVE.Field

theorem value_cast (e : ElemVal 8) :
    ((e.value : ℤ) : F) = e.limbs.get 0 + e.limbs.get 1 * 4294967296 + e.limbs.get 2 * K_390 +
      e.limbs.get 3 * K_391 + e.limbs.get 4 * K_392 + e.limbs.get 5 * K_393 + e.limbs.get 6 * K_394 +
      e.limbs.get 7 * K_395 := by
  rw [e.value_eq]
  simp only [rec8, ElemVal.limb_eq, K_390, K_391, K_392, K_393, K_394, K_395]
  push_cast
  ring

theorem K_1176_eq : (K_1176 : F) = ((p : ℕ) : F) ^ 2 := by
  simp only [K_1176, p]
  norm_num

theorem assertDistinctSlope_sound {Λ : ElemVal 8} {o : F}
    (h : AssertDistinctSlope_8_h16c15a53 Λ.limbs o) :
    slopeFactor (((Λ.value : ℤ) : F) - o) * slopeFactor (((Λ.value : ℤ) : F) + o) ≠ 0 := by
  unfold AssertDistinctSlope_8_h16c15a53 at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
    GatesDef.ne, exists_eq_left] at h
  obtain ⟨hne, -⟩ := h
  have hv : ((Λ.value : ℤ) : F) = 0 + Λ.limbs.get 0 * 1 + Λ.limbs.get 1 * 4294967296 +
      Λ.limbs.get 2 * K_390 + Λ.limbs.get 3 * K_391 + Λ.limbs.get 4 * K_392 + Λ.limbs.get 5 * K_393 +
      Λ.limbs.get 6 * K_394 + Λ.limbs.get 7 * K_395 := by
    rw [value_cast]; ring
  rw [hv]
  unfold slopeFactor
  rw [← K_1176_eq]
  exact hne

/-- Integer limbs of a balanced hinted element: three pieces minus `2^31`. -/
def balInt {n : ℕ} (g : List.Vector F n) (o : ℕ) : ℤ := pieceInt g o - 2 ^ 31

def balRec : ℤ := rec8 (fun _ => 1)

theorem rec8_bal_bounds {x : Fin 8 → ℤ} (h : ∀ i, -2 ^ 31 ≤ x i ∧ x i ≤ 2 ^ 31 - 1) :
    -2 ^ 31 * balRec ≤ rec8 x ∧ rec8 x ≤ (2 ^ 31 - 1) * balRec := by
  have h0 := h 0; have h1 := h 1; have h2 := h 2; have h3 := h 3
  have h4 := h 4; have h5 := h 5; have h6 := h 6; have h7 := h 7
  unfold balRec rec8
  norm_num at *
  constructor <;> linarith

/-- The bounds `Field.HintBalanced` attaches. -/
def balC : ElemC := uniC (-2 ^ 31) (2 ^ 31 - 1) (-2 ^ 31 * balRec) ((2 ^ 31 - 1) * balRec)

theorem bal_fits (hl : LookupSound RangeCheck 11) {n : ℕ} {g : List.Vector F n} {o : ℕ}
    (h : ∀ i : Fin 8, PieceRC g (o + 3 * i.val)) :
    Fits (fun i => balInt g (o + 3 * i.val)) balC := by
  have hb : ∀ i : Fin 8, -2 ^ 31 ≤ balInt g (o + 3 * i.val) ∧ balInt g (o + 3 * i.val) ≤ 2 ^ 31 - 1 := by
    intro i
    have := pieceInt_bounds hl (h i)
    unfold balInt
    constructor <;> linarith
  apply fits_uni hb
  exact rec8_bal_bounds hb

theorem balInt_cast {n : ℕ} (g : List.Vector F n) (o : ℕ) :
    ((balInt g o : ℤ) : F) =
      0 + g.toList.getD o 0 * 1 + g.toList.getD (o + 1) 0 * 2048 + g.toList.getD (o + 2) 0 * 4194304 -
        2147483648 := by
  unfold balInt
  push_cast
  rw [pieceInt_cast]

/-- A balanced element's value is below `p` in magnitude. -/
theorem bal_value_lt {e : ElemVal 8} (h : e.bnd = balC) : |e.value| < p := by
  have := uni_value h
  rw [abs_lt]
  simp only [balRec, rec8, p] at this ⊢
  norm_num at this ⊢
  constructor <;> linarith [this.1, this.2]

open ZolanaVE.Field in
/-- Normalise an `hxs` goal `limbLists es = [[L.get 0, …]]` to limb equalities and close them.
The extra terms unfold local element names. -/
syntax "limbs_tac" " [" Lean.Parser.Tactic.simpLemma,* "]" : tactic
macro_rules
  | `(tactic| limbs_tac [$ts,*]) => `(tactic| (
    simp only [limbLists, List.map, linElem, linX, List.map_cons, List.map_nil, List.sum_cons,
      List.sum_nil, mkElem_limbs, mkElem5_limbs, vec8_toList, vec5_toList, mkElem_int, mkElem5_limb,
      ElemVal.limb_eq, $ts,*]
    try simp only [List.Vector.get_eq_get_toList, Fin.coe_ofNat_eq_mod, List.Vector.toList_cons,
      List.Vector.toList_nil, List.get_eq_getElem, Nat.reduceMod, Nat.reduceMul, Nat.reduceAdd, List.getElem_cons_succ,
      List.getElem_cons_zero, getElem_eq_getD0, List.getD_cons_succ, List.getD_cons_zero, pieceInt_cast, balInt_cast, linElem, linX, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil, Gates,
      GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
      List.cons.injEq, and_true, Fin.coe_cast, Int.cast_add, Int.cast_sub, Int.cast_neg, Int.cast_mul]
    try (constructorm* _ ∧ _)
    all_goals (try push_cast); all_goals ring))

end ZolanaVE.P256
