import VerifiableEncryption.Curve.QuadAdd
import VerifiableEncryption.Circuit.Prelude

/-!
Mathematical justification for using the existing no-half-slope branch on
every middle step. For x-distinct curve points, the extra chord identity
LastSlope follows from the ordinary chord equation and the curve equations.
Unlike the native guard, it adds no unrelated native-modulus exclusion.

This module changes neither Go nor the extracted predicate. A repaired middle
gadget needs re-extraction and new bound-specific field certificates before
this lemma can be assembled into its witness/soundness statements.
-/

namespace ZolanaVE.P256.Completeness

theorem lastSlope_of_chord {dx dy tx ty slope : Fp}
    (hd : OnCurve dx dy) (ht : OnCurve tx ty) (hx : dx ≠ tx)
    (hchord : slope * (tx - dx) - ty + dy = 0) : LastSlope tx ty dx dy slope := by
  have hdiff : tx - dx ≠ 0 := sub_ne_zero.mpr hx.symm
  have hm : (tx - dx) *
      (slope * (dy + ty) - (dx + tx) ^ 2 + dx * tx + 3) = 0 := by
    unfold OnCurve at hd ht
    linear_combination (dy + ty) * hchord - hd + ht
  exact (mul_eq_zero.mp hm).resolve_left hdiff

/-- Constructive chord/LastSlope witnesses for the proposed field-only branch. -/
theorem field_only_chord_exists {dx dy tx ty : Fp}
    (hd : OnCurve dx dy) (ht : OnCurve tx ty) (hx : dx ≠ tx) :
    ∃ slope : Fp, slope * (tx - dx) - ty + dy = 0 ∧ LastSlope tx ty dx dy slope := by
  let slope := (ty - dy) / (tx - dx)
  have hmul : slope * (tx - dx) = ty - dy := div_mul_cancel₀ _ (sub_ne_zero.mpr hx.symm)
  have hchord : slope * (tx - dx) - ty + dy = 0 := by linear_combination hmul
  exact ⟨slope, hchord, lastSlope_of_chord hd ht hx hchord⟩

variable [Fact (Nat.Prime Order)]

/-- The IsZero inverse equation fixes the native-zero branch. The bounded
emulated flag must represent the same integer bit in Fp; bounds alone are
not substituted for that semantic connection. -/
theorem native_or_lastSlope (nativeProduct inverse : F) (flag : ℤ)
    (hbit : flag = 0 ∨ flag = 1)
    (hinverse : nativeProduct * inverse = 1 - (flag : F))
    {dx dy tx ty slope : Fp}
    (hfield : (flag : Fp) *
      (slope * (dy + ty) - (dx + tx) ^ 2 + dx * tx + 3) = 0) :
    nativeProduct ≠ 0 ∨ LastSlope tx ty dx dy slope := by
  rcases hbit with rfl | rfl
  · left
    intro hz
    rw [hz, zero_mul, Int.cast_zero, sub_zero] at hinverse
    exact one_ne_zero hinverse.symm
  · right
    simpa only [Int.cast_one, one_mul, LastSlope] using hfield

/-- Pure group soundness of the proposed fallback middle step, reusing the
existing native-guard implication and doubling-aware LastSlope theorem. -/
theorem quad_add_correct_with_fallback {xA yA tx ty dx dy slope second ix ox oy : Fp}
    (ha : OnCurve xA yA) (ht : OnCurve tx ty)
    (tangent half : ℤ) (htangent : |tangent| < p) (hhalf : |half| < p)
    (hq : halfQuartic tx ty (half : Fp) = 0)
    (cons : QuadAddCons xA yA tx ty (tangent : Fp) dx dy slope second ix ox oy)
    (inverse : F) (flag : ℤ) (hbit : flag = 0 ∨ flag = 1)
    (hinverse :
      (slopeFactor ((tangent : F) - (half : F)) *
        slopeFactor ((tangent : F) + (half : F))) * inverse = 1 - (flag : F))
    (hfield : (flag : Fp) *
      (slope * (dy + ty) - (dx + tx) ^ 2 + dx * tx + 3) = 0) :
    ∃ ho : OnCurve ox oy, mkPoint ho = 4 • mkPoint ha + mkPoint ht := by
  have hcases := native_or_lastSlope _ inverse flag hbit hinverse hfield
  rcases hcases with hn | hl
  · have hne := distinctSlope_guard (q := Order) htangent hhalf hn
    obtain ⟨hd, hdeq⟩ := tangent_double ha cons.tangent cons.dx cons.dy
    have hx := step_guard ha (by linear_combination cons.tangent) ht hq hne hd hdeq
    exact quad_add_correct ha ht cons (Or.inl hx)
  · exact quad_add_correct ha ht cons (Or.inr hl)

/-- A genuine native IsZero/field fallback witness exists whenever the
geometric LastSlope identity holds, including native alias inputs. -/
theorem fallback_flag_exists (nativeProduct : F) {dx dy tx ty slope : Fp}
    (hl : LastSlope tx ty dx dy slope) :
    ∃ flag : ℤ, (flag = 0 ∨ flag = 1) ∧
      nativeProduct * nativeProduct⁻¹ = 1 - (flag : F) ∧
      nativeProduct * (flag : F) = 0 ∧
      (flag : Fp) * (slope * (dy + ty) - (dx + tx) ^ 2 + dx * tx + 3) = 0 := by
  by_cases hz : nativeProduct = 0
  · refine ⟨1, Or.inr rfl, ?_, ?_, ?_⟩
    · simp [hz]
    · simp [hz]
    · simpa only [Int.cast_one, one_mul, LastSlope] using hl
  · refine ⟨0, Or.inl rfl, ?_, ?_, ?_⟩
    · simpa only [Int.cast_zero, sub_zero] using mul_inv_cancel₀ hz
    · simp
    · simp

end ZolanaVE.P256.Completeness
