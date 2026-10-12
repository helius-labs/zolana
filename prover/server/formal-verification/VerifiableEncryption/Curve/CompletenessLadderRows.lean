import VerifiableEncryption.Curve.LadderTable
import VerifiableEncryption.Curve.CompletenessLadderInputs
import VerifiableEncryption.Curve.Slots

/-! The actual twelve-column row layout, constructed from a reduced slot
point and its balanced half slope. Packing changes the representation of y;
the half-slope column retains its original sign, as in the production table.
Generation and kernel validation are recorded separately. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

/-- All four geometric chord pairs used by the eight eager slot additions.
Negating either y coordinate preserves these distinct-x conditions. -/
theorem slotChordPairs (Q : P) (hQ : Q ≠ 0) (scalar : ℤ)
    (hs : ¬Exceptional (scalar : ScalarField)) :
    (Q ≠ scalar • Q ∧ Q ≠ -(scalar • Q)) ∧
    (3 • Q ≠ 3 • (scalar • Q) ∧ 3 • Q ≠ -(3 • (scalar • Q))) ∧
    (3 • Q ≠ scalar • Q ∧ 3 • Q ≠ -(scalar • Q)) ∧
    (Q ≠ 3 • (scalar • Q) ∧ Q ≠ -(3 • (scalar • Q))) := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := ladder_initial_collisions hQ scalar hs
  have hqr : Q ≠ scalar • Q ∧ Q ≠ -(scalar • Q) := by
    refine ⟨Ne.symm h1, ?_⟩
    intro he
    exact h2 (by simpa only [neg_neg] using (congrArg Neg.neg he).symm)
  refine ⟨hqr, three_ne hqr.1 hqr.2, ⟨Ne.symm h3, ?_⟩, ⟨Ne.symm h5, ?_⟩⟩
  · intro he
    exact h4 (by simpa only [neg_neg] using (congrArg Neg.neg he).symm)
  · intro he
    exact h6 (by simpa only [neg_neg] using (congrArg Neg.neg he).symm)

def signedLadderRow (X Y H : ElemVal 8) (s : ℤ) : List.Vector F 12 :=
  vec![X.limbs.get 0, X.limbs.get 1, X.limbs.get 2, X.limbs.get 3,
    X.limbs.get 4, X.limbs.get 5, X.limbs.get 6, X.limbs.get 7,
    (packInts s Y 0 : F), (packInts s Y 3 : F), (packInts s Y 6 : F),
    (H.value : F)]

theorem signedLadderRow_ok (X Y H : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = reducedC) (hH : H.bnd = balC)
    (hP : OnCurve (X.value : Fp) (Y.value : Fp))
    (hq : halfQuartic (X.value : Fp) (Y.value : Fp) (H.value : Fp) = 0)
    (s : ℤ) (hs : s = 1 ∨ s = -1) :
    RowOK (signedLadderRow X Y H s) (s • mkPoint hP) := by
  apply rowOK_of2 hX hY hH hP hq hs
  · exact vec8_eta X.limbs
  · rfl
  · rfl
  · rfl
  · rfl
  · intro he
    rw [he, one_zsmul]
  · intro he
    rw [he, neg_one_zsmul]

/-- The row unpacked by the native Quad callback has the exact wide bound,
while retaining the chosen signed point. No lookup soundness is used. -/
theorem signedLadderRow_unpack (X Y H : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = reducedC) (hH : H.bnd = balC)
    (hP : OnCurve (X.value : Fp) (Y.value : Fp))
    (hq : halfQuartic (X.value : Fp) (Y.value : Fp) (H.value : Fp) = 0)
    (s : ℤ) (hs : s = 1 ∨ s = -1) :
    ∃ U : ElemVal 8, U.bnd = unpackC ∧
      U.limbs = vec![(packInts s Y 0 : F), 0, 0,
        (packInts s Y 3 : F), 0, 0, (packInts s Y 6 : F), 0] ∧
      ∃ hU : OnCurve (X.value : Fp) (U.value : Fp),
        mkPoint hU = s • mkPoint hP := by
  have hr := signedLadderRow_ok X Y H hX hY hH hP hq s hs
  obtain ⟨XX, U, hon, hh, hhalf, hXX, hU, hx, hy, _, _, _, _, hp⟩ := hr
  have hxe : XX.limbs = X.limbs := by
    calc
      XX.limbs = vec![X.limbs.get 0, X.limbs.get 1, X.limbs.get 2, X.limbs.get 3,
          X.limbs.get 4, X.limbs.get 5, X.limbs.get 6, X.limbs.get 7] := hx.symm
      _ = X.limbs := vec8_eta X.limbs
  have hxv : XX.value = X.value := by
    rw [← (reduced_vals hXX).2, ← (reduced_vals hX).2, hxe]
  refine ⟨U, hU, ?_, ?_⟩
  · simpa only [signedLadderRow, List.Vector.get_cons_zero,
      List.Vector.get_cons_succ] using hy.symm
  · have hon' : OnCurve (X.value : Fp) (U.value : Fp) := by
      simpa only [hxv] using hon
    refine ⟨hon', ?_⟩
    have he : mkPoint hon' = mkPoint hon := mkPoint_inj.mpr ⟨by rw [hxv], rfl⟩
    exact he.trans hp

def ladderRowSlot (i : Fin 16) : Fin 8 :=
  ⟨if i.val < 8 then i.val else 15 - i.val, by split_ifs <;> omega⟩

def ladderRowSign (i : Fin 16) : ℤ := if i.val % 2 = 0 then -1 else 1

/-- Native A0..A7 are constructed in dependency order; the table uses this
permutation to put them in `Ladder.slotPoint` order. -/
def nativeSlotIndex (j : Fin 8) : Fin 8 :=
  (vec![(1 : Fin 8), 5, 6, 0, 3, 7, 4, 2]).get j

noncomputable def nativeSlotPoint (j : Fin 8) (Q R : P) : P :=
  (vec![Q + R, 3 • Q + 3 • R, 3 • Q + R, Q + 3 • R,
    Q - R, Q - 3 • R, 3 • Q - R, 3 • Q - 3 • R]).get j

theorem nativeSlotPoint_order (j : Fin 8) (Q R : P) :
    nativeSlotPoint (nativeSlotIndex j) Q R = Ladder.slotPoint j.val Q R := by
  fin_cases j <;> rfl

def constructedLadderRows (X Y H : Fin 8 → ElemVal 8) :
    List.Vector (List.Vector F 12) 16 :=
  List.Vector.ofFn fun i =>
    signedLadderRow (X (ladderRowSlot i)) (Y (ladderRowSlot i))
      (H (ladderRowSlot i)) (ladderRowSign i)

/-- The mirrored sixteen-row table is derived from the eight constructed
slot coordinates and quartic roots. Slot identities are mathematical facts
from the Add/Triple constructors, rather than assumed table satisfiability. -/
theorem constructedLadderRows_ok (X Y H : Fin 8 → ElemVal 8)
    (hX : ∀ j, (X j).bnd = reducedC) (hY : ∀ j, (Y j).bnd = reducedC)
    (hH : ∀ j, (H j).bnd = balC)
    (hon : ∀ j, OnCurve ((X j).value : Fp) ((Y j).value : Fp))
    (hq : ∀ j, halfQuartic ((X j).value : Fp) ((Y j).value : Fp)
      ((H j).value : Fp) = 0)
    (Q R : P) (hp : ∀ j, mkPoint (hon j) = Ladder.slotPoint j.val Q R) :
    TableOK (constructedLadderRows X Y H) Q R := by
  intro i
  have hs : ladderRowSign i = 1 ∨ ladderRowSign i = -1 := by
    unfold ladderRowSign
    split_ifs <;> simp
  have hr := signedLadderRow_ok _ _ _ (hX (ladderRowSlot i))
    (hY (ladderRowSlot i)) (hH (ladderRowSlot i))
    (hon (ladderRowSlot i)) (hq (ladderRowSlot i)) (ladderRowSign i) hs
  have he : ladderRowSign i • mkPoint (hon (ladderRowSlot i)) =
      Ladder.rowPoint i.val Q R := by
    rw [hp]
    unfold ladderRowSign Ladder.rowPoint
    change (if i.val % 2 = 0 then (-1 : ℤ) else 1) •
      Ladder.slotPoint (if i.val < 8 then i.val else 15 - i.val) Q R = _
    split_ifs <;> simp only [neg_one_zsmul, one_zsmul]
  rw [he] at hr
  simpa only [constructedLadderRows, List.Vector.get_ofFn] using hr

end ZolanaVE.P256.Completeness
