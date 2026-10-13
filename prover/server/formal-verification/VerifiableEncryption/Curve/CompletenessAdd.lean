import VerifiableEncryption.Curve.CompletenessAddMath
import VerifiableEncryption.Curve.CompletenessAddNative
import VerifiableEncryption.Curve.CompletenessAddArithmetic
import VerifiableEncryption.Curve.CompletenessAddOutputs

/-! Construct the actual CompleteAdd predicate on the full finite reduced,
canonical-x noninverse domain, including equal-point tangent additions. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem completeAdd_with_point_complete (hr : RangeComplete) (PX PY QX QY : ElemVal 8)
    (hPX : PX.bnd = reducedC) (hPY : PY.bnd = reducedC)
    (hQX : QX.bnd = reducedC) (hQY : QY.bnd = reducedC)
    (hcPX : limbNat PX.limbs < p) (hcQX : limbNat QX.limbs < p)
    (hP : OnCurve (PX.value : Fp) (PY.value : Fp))
    (hQ : OnCurve (QX.value : Fp) (QY.value : Fp)) (hne : mkPoint hP ≠ -mkPoint hQ) :
    ∃ RX RY : ElemVal 8, RX.bnd = reducedC ∧ RY.bnd = reducedC ∧
      limbNat RX.limbs < p ∧ limbNat RY.limbs < p ∧
      (∃ hR : OnCurve (RX.value : Fp) (RY.value : Fp),
        mkPoint hP + mkPoint hQ = mkPoint hR) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (RX.limbs ::ᵥ RY.limbs ::ᵥ List.Vector.nil) →
        CompleteAdd_8_8_8_8_h3f5cf0cd PX.limbs PY.limbs QX.limbs QY.limbs k := by
  obtain ⟨b, inverse, hbool, hguard, hbNat⟩ := sameX_native_witness PX.limbs QX.limbs
    (reduced_vals hPX).1 (reduced_vals hQX).1
  have hbFp := sameX_fp_iff PX QX hPX hQX hcPX hcQX b hbNat
  obtain ⟨l, hxFlag, hyFlag, hSlope⟩ := affineSlope_given_flag b hbFp hP hQ hne
  let L := slopeElem l
  let x : Fp := l ^ 2 - (PX.value : Fp) - (QX.value : Fp)
  let y : Fp := l * ((PX.value : Fp) - x) - (PY.value : Fp)
  have hMath : ∃ hR : OnCurve x y, mkPoint hP + mkPoint hQ = mkPoint hR := by
    apply complete_add hP hQ (l := l) (s := if b then 1 else 0)
      (by cases b <;> simp) ?_ hxFlag hyFlag ?_ rfl rfl
    · intro hz he
      have ht := hbFp.mpr he
      rw [ht] at hz
      exact one_ne_zero hz
    · linear_combination hSlope
  let RX := canonicalFpElem x
  let RY := canonicalFpElem y
  have cRX : (RX.value : Fp) = x := canonicalFpElem_cast x
  have cRY : (RY.value : Fp) = y := canonicalFpElem_cast y
  obtain ⟨hRaw, hpRaw⟩ := hMath
  have hR : OnCurve (RX.value : Fp) (RY.value : Fp) := by rw [cRX, cRY]; exact hRaw
  have hpR : mkPoint hP + mkPoint hQ = mkPoint hR :=
    hpRaw.trans (mkPoint_inj.mpr ⟨cRX.symm, cRY.symm⟩)
  have cx := addFlag_complete hr PX QX b hPX hQX hxFlag
  have cy := addFlag_complete hr PY QY b hPY hQY hyFlag
  have cl := addSlope_complete hr PX PY QX QY b hPX hPY hQX hQY l hSlope
  have cxOutput := addX_complete hr L PX QX rfl hPX hQX l x (slopeElem_cast l) rfl
  have cyOutput := addY_complete hr L PX RX PY rfl hPX rfl hPY l y (slopeElem_cast l) (by
    rw [cRX])
  refine ⟨RX, RY, rfl, rfl,
    by change limbNat (canonicalFpElem x).limbs < p
       unfold canonicalFpElem
       rw [canonicalNatElem_limbNat]; exact ZMod.val_lt x,
    by change limbNat (canonicalFpElem y).limbs < p
       unfold canonicalFpElem
       rw [canonicalNatElem_limbNat]; exact ZMod.val_lt y,
    ⟨hR, hpR⟩, ?_⟩
  intro k hk
  exact completeAdd_native PX PY QX QY L RX RY b inverse (rawSlopePieces l) (slopePieces l)
    hbool hguard (canonicalP_complete PX.limbs (reduced_vals hPX).1 hcPX)
    (canonicalP_complete QX.limbs (reduced_vals hQX).1 hcQX)
    (slopePieces_ranges hr l) (slopePieces_limb l) cx cy cl cxOutput cyOutput k hk

end ZolanaVE.P256.Completeness
