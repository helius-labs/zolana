import VerifiableEncryption.Curve.CompletenessLadderBits
import VerifiableEncryption.Curve.CompletenessLadderHalfTangent
import VerifiableEncryption.Curve.CompletenessLimbs
import VerifiableEncryption.ParameterCertificates.CurveOrderScalar

/-!
Literal arithmetic certificate source for the authorized offline search result.
No Go hint or circuit was executed. These statements passed ordinary kernel
checking after Lean validation was authorized.
The result concerns the actual scalar-two production decomposition and its
native guard. It does not prove that every alternative decomposition is
impossible. Arbitrary half-quartic roots at this primitive slot are covered
by half-point/tangent uniqueness.

For the pinned lattice RationalReconstruct source, k=2 initializes (r1,t1)
to (2,1), and the while condition is false because 2<sqrt(n). The production
wrapper therefore emits numerator=2, denominator=1 and sign=true. This source
trace is separate from a formal semantics theorem about the Go program.
-/

namespace ZolanaVE.P256.Completeness.Counterexample

open ZolanaVE.Field
open ZolanaVE.ParameterCertificates.CurveOrderScalar

def qx : ℕ := 12522962446035231127621707147412659097503212279703474269501961773398358543680
def qy : ℕ := 70199231857690515084037475016069317608327796589084722622064003299853969014198
def hx : ℕ := 94452787275698337476403564053178286618871356376094913925697927831369508389166
def hy : ℕ := 30526978040644247442361995366694392391154411693316533922618974064732730295178

def tangentValue : ℤ := 44276850581706675402633548879493395649342029952622209993727888124831289624929
def halfSlopeValue : ℕ := 93403481500488848582310303815171452969292477863084138545503947370611616724639
def halfBalanced : ℤ := -22388607709867400180387143134236120560793665552206175650029683938255481129312

theorem q_canonical : qx < p ∧ qy < p := by decide +kernel
theorem h_canonical : hx < p ∧ hy < p := by decide +kernel
theorem q_onCurve : OnCurve (qx : Fp) (qy : Fp) := by
  unfold OnCurve
  decide +kernel
theorem h_onCurve : OnCurve (hx : Fp) (hy : Fp) := by
  unfold OnCurve
  decide +kernel

def Q : P := mkPoint q_onCurve
def H : P := mkPoint h_onCurve
def rawH : Coordinates := some ((hx : Fp), (hy : Fp))
def rawQ : Coordinates := some ((qx : Fp), (qy : Fp))

theorem q_nonzero : Q ≠ 0 := mkPoint_ne_zero q_onCurve
theorem h_nonzero : H ≠ 0 := mkPoint_ne_zero h_onCurve

theorem raw_double_check : rawAdd rawH rawH = rawQ := by decide +kernel

theorem q_eq_two_h : Q = 2 • H := by
  have hr : Represents rawH H := ⟨nonsingular_of_onCurve h_onCurve, rfl⟩
  have result := rawAdd_sound hr hr
  rw [raw_double_check] at result
  obtain ⟨hp, he⟩ := result
  have hq : (WeierstrassCurve.Affine.Point.some hp : P) = Q := rfl
  have hsum : H + H = Q := he.trans hq
  simpa only [two_nsmul] using hsum.symm

theorem tangent_check :
    2 * (tangentValue : Fp) * (-(qy : Fp)) = 3 * (qx : Fp) ^ 2 - 3 := by decide +kernel

def rawThird : Coordinates := rawAdd rawH rawQ
def thirdX : Fp := match rawThird with | none => 0 | some xy => xy.1
def thirdY : Fp := match rawThird with | none => 0 | some xy => xy.2

theorem third_finite_check : rawThird ≠ none := by decide +kernel
theorem half_tangent_check :
    2 * (halfSlopeValue : Fp) * thirdY = 3 * thirdX ^ 2 - 3 := by decide +kernel

theorem third_representation : Represents rawThird (3 • H) := by
  have hr : Represents rawH H := ⟨nonsingular_of_onCurve h_onCurve, rfl⟩
  have hq : Represents rawQ Q := ⟨nonsingular_of_onCurve q_onCurve, rfl⟩
  have result := rawAdd_sound hr hq
  change Represents rawThird (H + Q) at result
  have he : H + Q = 3 • H := by rw [q_eq_two_h]; abel
  rw [he] at result
  exact result

theorem third_affine : ∃ ht : OnCurve thirdX thirdY, mkPoint ht = 3 • H := by
  have rep := third_representation
  cases hraw : rawThird with
  | none => exact False.elim (third_finite_check hraw)
  | some xy =>
    rcases xy with ⟨x, y⟩
    have hs : Represents (some (x, y)) (3 • H) := by simpa only [hraw] using rep
    obtain ⟨hp, he⟩ := hs
    simp only [thirdX, thirdY, hraw]
    exact ⟨(equation_iff_onCurve x y).mp hp.1, he.symm⟩

def slotX : Fp := (halfSlopeValue : Fp) ^ 2 - 2 * thirdX
def slotY : Fp := -((halfSlopeValue : Fp) * (thirdX - slotX) - thirdY)

theorem slot_affine : ∃ ht : OnCurve slotX slotY,
    mkPoint ht = Ladder.slotPoint 0 Q (-(2 • Q)) := by
  obtain ⟨ht, he⟩ := third_affine
  obtain ⟨hd, hdEq⟩ := tangent_double ht half_tangent_check rfl rfl
  obtain ⟨hn, hnEq⟩ := neg_mkPoint hd
  refine ⟨hn, ?_⟩
  have hs : Ladder.slotPoint 0 Q (-(2 • Q)) = -mkPoint hd := by
    rw [← hdEq, he]
    simp only [Ladder.slotPoint, q_eq_two_h]
    abel
  exact hnEq.symm.trans hs.symm

theorem slot_half_quartic : halfQuartic slotX slotY (-(halfSlopeValue : Fp)) = 0 := by
  simp only [halfQuartic, slotX, slotY]
  linear_combination 4 * half_tangent_check

theorem every_slot_half_root (l : Fp) (hl : halfQuartic slotX slotY l = 0) :
    l = -(halfSlopeValue : Fp) := by
  obtain ⟨ht, _⟩ := slot_affine
  exact halfQuartic_root_unique ht hl slot_half_quartic

theorem half_slot_zero :
    halfCoefficient • Ladder.slotPoint 0 Q (-((2 : ℕ) • Q)) = -((3 : ℕ) • H) := by
  have hc : (2 : ℕ) • (-((3 : ℕ) • H)) = Ladder.slotPoint 0 Q (-((2 : ℕ) • Q)) := by
    simp only [Ladder.slotPoint, q_eq_two_h]
    abel
  have hd := point_half_double (Ladder.slotPoint 0 Q (-((2 : ℕ) • Q)))
  have hz : (2 : ℕ) • (halfCoefficient • Ladder.slotPoint 0 Q (-((2 : ℕ) • Q)) - (-((3 : ℕ) • H))) = 0 := by
    rw [nsmul_sub, hd, hc, sub_self]
  exact sub_eq_zero.mp (no_two_torsion _ hz)

theorem scalar_two_reconstruction_loop_false : 2 < Nat.sqrt n := by
  have h : 3 ≤ Nat.sqrt n := Nat.le_sqrt'.mpr (by norm_num [n])
  omega

theorem scalar_two_nonexceptional : ¬Exceptional (2 : ScalarField) := by decide +kernel
theorem scalar_two_nonzero : (2 : ℕ) % n ≠ 0 := by decide +kernel
theorem first_selector : ladderSelector 2 1 128 = 0 := by decide +kernel

theorem first_row : Ladder.rowPoint (ladderSelector 2 1 128) Q (-(2 • Q)) = 3 • Q := by
  rw [first_selector]
  simp only [Ladder.rowPoint, Ladder.slotPoint]
  norm_num <;> abel

theorem tangent_balanced_value : (slopeElem (tangentValue : Fp)).value = tangentValue := by
  rw [slopeElem_value]
  change ((balancedUnsigned (tangentValue : Fp) : ℕ) : ℤ) - balanceOffset = tangentValue
  decide +kernel

theorem half_balanced_value : (slopeElem (halfSlopeValue : Fp)).value = halfBalanced := by
  rw [slopeElem_value]
  decide +kernel

/-- Slot zero is -3Q, so the production table carries the tangent of -3H.
The ± guard is symmetric, but this fixes its actual stored sign. -/
theorem slot_half_balanced_value : (slopeElem (-(halfSlopeValue : Fp))).value = -halfBalanced := by
  rw [slopeElem_value]
  decide +kernel

theorem tangent_unique (l : Fp)
    (hl : 2 * l * (-(qy : Fp)) = 3 * (qx : Fp) ^ 2 - 3) : l = (tangentValue : Fp) := by
  have hd : 2 * (-(qy : Fp)) ≠ 0 := by decide +kernel
  apply mul_right_cancel₀ hd
  linear_combination hl - tangent_check

theorem actual_half_tangent_unique (l : Fp)
    (hl : 2 * l * thirdY = 3 * thirdX ^ 2 - 3) : l = (halfSlopeValue : Fp) := by
  have hd : 2 * thirdY ≠ 0 := by decide +kernel
  apply mul_right_cancel₀ hd
  linear_combination hl - half_tangent_check

/-- An interior representative has no second permitted balanced integer
representative. This does not assert uniqueness of an arbitrary quartic root. -/
theorem balanced_representative_unique (e : ElemVal 8) (he : e.bnd = balC) (literal : ℤ)
    (hgaps : literal - p < -2 ^ 31 * balRec ∧ (2 ^ 31 - 1) * balRec < literal + p)
    (hcast : (e.value : Fp) = (literal : Fp)) : e.value = literal := by
  have hv := uni_value he
  change -2 ^ 31 * balRec ≤ e.value ∧ e.value ≤ (2 ^ 31 - 1) * balRec at hv
  have hdiv := ((ZMod.intCast_eq_intCast_iff e.value literal p).mp hcast).dvd
  have hsmall : |literal - e.value| < (p : ℤ) := by
    rw [abs_lt]
    constructor <;> linarith [hv.1, hv.2, hgaps.1, hgaps.2]
  have habs : (literal - e.value).natAbs < Int.natAbs (p : ℤ) := by
    have h : ((literal - e.value).natAbs : ℤ) < (p : ℤ) := by
      simpa only [Int.natCast_natAbs] using hsmall
    exact_mod_cast h
  have hz := Int.eq_zero_of_dvd_of_natAbs_lt_natAbs hdiv habs
  exact (sub_eq_zero.mp hz).symm

theorem tangent_rep_unique (e : ElemVal 8) (he : e.bnd = balC)
    (hcast : (e.value : Fp) = (tangentValue : Fp)) : e.value = tangentValue :=
  balanced_representative_unique e he tangentValue
    (by norm_num [tangentValue, p, balRec, rec8]) hcast

theorem slot_half_rep_unique (e : ElemVal 8) (he : e.bnd = balC)
    (hcast : (e.value : Fp) = ((-halfBalanced : ℤ) : Fp)) : e.value = -halfBalanced :=
  balanced_representative_unique e he (-halfBalanced)
    (by norm_num [halfBalanced, p, balRec, rec8]) hcast

theorem balanced_sum_is_Order : tangentValue + halfBalanced = (Order : ℤ) := by
  norm_num [tangentValue, halfBalanced, Order]

theorem native_guard_zero :
    slopeFactor ((tangentValue : F) - ((-halfBalanced : ℤ) : F)) *
      slopeFactor ((tangentValue : F) + ((-halfBalanced : ℤ) : F)) = 0 := by
  have hz : (tangentValue : F) - ((-halfBalanced : ℤ) : F) = 0 := by
    have h := congrArg (fun z : ℤ => (z : F)) balanced_sum_is_Order
    push_cast at h
    simpa only [Int.cast_neg, ZMod.natCast_self, sub_neg_eq_add] using h
  rw [hz]
  simp [slopeFactor]

/-- Failure of the actual extracted native guard on the concrete balanced
tangent/slot-half inputs, not merely failure of an abstract Fp inequality. -/
theorem extracted_guard_impossible :
    ¬AssertDistinctSlope_8_hf8ff5ddf (slopeElem (tangentValue : Fp)).limbs
      (((slopeElem (-(halfSlopeValue : Fp))).value : ℤ) : F) := by
  intro h
  have hn := assertDistinctSlope_sound h
  rw [tangent_balanced_value, slot_half_balanced_value] at hn
  exact hn native_guard_zero

/-- Every permitted balanced encoding of the actual tangent and actual
slot-half tangent fails. Alternative arbitrary quartic roots are not covered. -/
theorem every_actual_balanced_guard_impossible (tangent half : ElemVal 8)
    (ht : tangent.bnd = balC) (hh : half.bnd = balC)
    (htangent : 2 * (tangent.value : Fp) * (-(qy : Fp)) = 3 * (qx : Fp) ^ 2 - 3)
    (hhalf : 2 * (half.value : Fp) * (-thirdY) = 3 * thirdX ^ 2 - 3) :
    ¬AssertDistinctSlope_8_hf8ff5ddf tangent.limbs ((half.value : ℤ) : F) := by
  have htv := tangent_rep_unique tangent ht (tangent_unique _ htangent)
  have hopp : 2 * (-(half.value : Fp)) * thirdY = 3 * thirdX ^ 2 - 3 := by
    linear_combination hhalf
  have hf : (half.value : Fp) = -(halfSlopeValue : Fp) :=
    neg_eq_iff_eq_neg.mp (actual_half_tangent_unique _ hopp)
  have hcast : (half.value : Fp) = ((-halfBalanced : ℤ) : Fp) := by
    rw [hf, ← slot_half_balanced_value]
    exact (slopeElem_cast (-(halfSlopeValue : Fp))).symm
  have hhv := slot_half_rep_unique half hh hcast
  intro h
  have hn := assertDistinctSlope_sound h
  rw [htv, hhv] at hn
  exact hn native_guard_zero

/-- The half-quartic constraint itself fixes the half slope here, by the
proved no-two-torsion/half-root uniqueness result. The primitive candidate
cannot escape the native failure with a different balanced slope/root. -/
theorem every_quartic_balanced_guard_impossible (tangent half : ElemVal 8)
    (ht : tangent.bnd = balC) (hh : half.bnd = balC)
    (htangent : 2 * (tangent.value : Fp) * (-(qy : Fp)) = 3 * (qx : Fp) ^ 2 - 3)
    (hhalf : halfQuartic slotX slotY (half.value : Fp) = 0) :
    ¬AssertDistinctSlope_8_hf8ff5ddf tangent.limbs ((half.value : ℤ) : F) := by
  have htv := tangent_rep_unique tangent ht (tangent_unique _ htangent)
  have hf := every_slot_half_root (half.value : Fp) hhalf
  have hcast : (half.value : Fp) = ((-halfBalanced : ℤ) : Fp) := by
    rw [hf, ← slot_half_balanced_value]
    exact (slopeElem_cast (-(halfSlopeValue : Fp))).symm
  have hhv := slot_half_rep_unique half hh hcast
  intro h
  have hn := assertDistinctSlope_sound h
  rw [htv, hhv] at hn
  exact hn native_guard_zero

end ZolanaVE.P256.Completeness.Counterexample
