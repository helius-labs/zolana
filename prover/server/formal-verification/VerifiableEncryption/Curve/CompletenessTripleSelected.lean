import VerifiableEncryption.Curve.CompletenessTripleMath
import VerifiableEncryption.Curve.CompletenessTripleSelectedY
import VerifiableEncryption.Curve.CompletenessTripleSelectedArithmetic

/-! Construct the actual selected-y triple gadget for every finite bounded
input point. Its arithmetic constructors build both balanced slopes and every
primitive witness; the point geometry discharges their value equations. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem triple_hffcb8921_complete (hr : RangeComplete) (X Y : ElemVal 8)
    (hX : X.bnd = reducedC) (hY : Y.bnd = selC)
    (hP : OnCurve (X.value : Fp) (Y.value : Fp)) :
    ∃ RX RY : ElemVal 8, RX.bnd = reducedC ∧ RY.bnd = reducedC ∧
      limbNat RX.limbs < p ∧ limbNat RY.limbs < p ∧
      (∃ hT : OnCurve (RX.value : Fp) (RY.value : Fp), mkPoint hT = 3 • mkPoint hP) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (RX.limbs ::ᵥ RY.limbs ::ᵥ List.Vector.nil) → Triple_8_8_hffcb8921 X.limbs Y.limbs k := by
  obtain ⟨l, dx, r, x3, y3, hl, hdx, hratio, hx3, hy3, hT, hpT⟩ := triple_slopes_exist hP
  have tan := tripleSelectedTangent_complete hr X Y hX hY l hl
  obtain ⟨DX, hDX, vDX, dxActual⟩ := tripleDoubleX_complete X hX l
  have cDX : (DX.value : Fp) = dx := vDX.trans hdx.symm
  have ratio := tripleSelectedRatio_complete hr X DX Y hX hDX hY r (by
    rw [cDX]
    exact hratio)
  let RX := canonicalFpElem x3
  have hRX : RX.bnd = reducedC := rfl
  have cRX : (RX.value : Fp) = x3 := canonicalFpElem_cast x3
  have rxActual := tripleX_complete hr X DX hX hDX l r x3 (by
    rw [cDX]
    exact hx3)
  let RY := canonicalFpElem y3
  have cRY : (RY.value : Fp) = y3 := canonicalFpElem_cast y3
  have ryActual := tripleSelectedY_complete hr X RX Y hX hRX hY l r y3 (by
    rw [cRX]
    exact hy3)
  have hO : OnCurve (RX.value : Fp) (RY.value : Fp) := by rw [cRX, cRY]; exact hT
  have pO : mkPoint hO = 3 • mkPoint hP := by
    rw [← hpT]
    exact mkPoint_inj.mpr ⟨cRX, cRY⟩
  refine ⟨RX, RY, hRX, rfl,
    by change limbNat (canonicalFpElem x3).limbs < p
       unfold canonicalFpElem
       rw [canonicalNatElem_limbNat]; exact ZMod.val_lt x3,
    by change limbNat (canonicalFpElem y3).limbs < p
       unfold canonicalFpElem
       rw [canonicalNatElem_limbNat]; exact ZMod.val_lt y3,
    ⟨hO, pO⟩, ?_⟩
  intro k hk
  exact triple_hffcb8921_of_arithmetic hr X.limbs Y.limbs DX.limbs RX.limbs RY.limbs
    l r tan dxActual ratio rxActual ryActual k hk

end ZolanaVE.P256.Completeness
