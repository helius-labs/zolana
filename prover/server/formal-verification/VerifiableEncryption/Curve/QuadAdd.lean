import VerifiableEncryption.Curve.Guards

/-!
Group law of `curve.quadrupleAndAddLazy`: `acc ← 4·acc + T`.

The gadget doubles `A` with the tangent slope `l`, adds `T` with the hinted
chord slope `μ`, and adds the double once more with the hinted slope `ν`.
The second addition needs no guard: a collision `x(D + T) = x(D)` forces
`y(D) = 0` through the `ν` constraint. The first addition is guarded either
by the distinct-slope check (`xD ≠ xT`) or, on the last step, by a second
`μ` equation that also covers `T = D`.
-/

namespace ZolanaVE.P256

/-- The constraints of one quadruple-and-add step over `Fp`. -/
structure QuadAddCons (xA yA xT yT l dX dY μ ν iX oX oY : Fp) : Prop where
  tangent : 2 * l * yA = 3 * xA ^ 2 - 3
  dx : dX = l ^ 2 - 2 * xA
  dy : dY = l * (xA - dX) - yA
  chord : μ * (xT - dX) - yT + dY = 0
  ix : iX = μ ^ 2 - dX - xT
  second : ν * (iX - dX) + 2 * μ * (xT - dX) - 2 * yT = 0
  ox : oX = ν * (ν + 2 * μ) + xT
  oy : oY = (μ + ν) * (oX - dX) + μ * (xT - dX) - yT

/-- The last step replaces the distinct-x guard by a second slope equation. -/
def LastSlope (xT yT dX dY μ : Fp) : Prop :=
  μ * (dY + yT) - (dX + xT) ^ 2 + dX * xT + 3 = 0

theorem quad_add_correct {xA yA xT yT l dX dY μ ν iX oX oY : Fp} (hA : OnCurve xA yA)
    (hT : OnCurve xT yT) (c : QuadAddCons xA yA xT yT l dX dY μ ν iX oX oY)
    (guard : dX ≠ xT ∨ LastSlope xT yT dX dY μ) :
    ∃ hO : OnCurve oX oY, mkPoint hO = 4 • mkPoint hA + mkPoint hT := by
  obtain ⟨hD, hDeq⟩ := tangent_double hA c.tangent c.dx c.dy
  have hdY : dY ≠ 0 := y_ne_zero_of_onCurve hD
  have h2 : (2 : Fp) ≠ 0 := two_ne_zero_Fp
  have hI : ∃ hI : OnCurve iX (μ * (dX - iX) - dY), mkPoint hD + mkPoint hT = mkPoint hI := by
    by_cases hx : dX = xT
    · rcases guard with g | g
      · exact absurd hx g
      subst hx
      rcases eq_or_eq_neg_of_x_eq hD hT rfl with he | he
      · obtain ⟨-, hyy⟩ := mkPoint_inj.mp he
        subst hyy
        obtain ⟨hI, hIeq⟩ := tangent_double (l := μ) (xd := iX) (yd := μ * (dX - iX) - dY) hD
          (by unfold LastSlope at g; linear_combination g) (by rw [c.ix]; ring) rfl
        exact ⟨hI, by rw [← two_nsmul, hIeq]⟩
      · obtain ⟨hn, hneq⟩ := neg_mkPoint hT
        rw [hneq] at he
        obtain ⟨-, hyy⟩ := mkPoint_inj.mp he
        exact absurd (by have := c.chord; rw [hyy, sub_self, mul_zero] at this
                         have h2y : (2 : Fp) * dY = 0 := by linear_combination this + 2 * hyy
                         exact (mul_eq_zero.mp h2y).resolve_left h2) hdY
    · exact slope_add hD hT hx (by linear_combination c.chord) c.ix rfl
  obtain ⟨hI, hIeq⟩ := hI
  have hx2 : iX ≠ dX := by
    intro he
    apply hdY
    have := c.second
    rw [he, sub_self, mul_zero, zero_add] at this
    have h2y : (2 : Fp) * dY = 0 := by linear_combination 2 * c.chord - this
    exact (mul_eq_zero.mp h2y).resolve_left h2
  obtain ⟨hO, hOeq⟩ := slope_add hI hD hx2 (l := -(μ + ν)) (xs := oX) (ys := oY)
    (by linear_combination c.second - 2 * c.chord)
    (by rw [c.ox, c.ix]; ring)
    (by rw [c.oy]; linear_combination c.second - c.chord)
  refine ⟨hO, ?_⟩
  rw [← hOeq, ← hIeq, ← hDeq]
  rw [show (4 : ℕ) = 2 + 2 from rfl, add_nsmul]
  abel

end ZolanaVE.P256
