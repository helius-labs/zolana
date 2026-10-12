import VerifiableEncryption.Curve.Guards

/-! Shared affine-coordinate witness for every nonidentity curve point. -/

namespace ZolanaVE.P256.Completeness

theorem affine_of_nonzero (T : P) (hT : T ≠ 0) :
    ∃ (x y : Fp) (h : OnCurve x y), mkPoint h = T := by
  cases T with
  | zero => exact False.elim (hT rfl)
  | @some x y hp =>
    refine ⟨x, y, (equation_iff_onCurve x y).mp hp.1, ?_⟩
    rfl

end ZolanaVE.P256.Completeness
