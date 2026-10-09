import VerifiableEncryption.Curve.LadderTable
import VerifiableEncryption.Curve.Slots

/-!
The ladder's last step: the looked-up row plus `3R`, then the doubling-aware
quadruple-and-add.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem ladder_last (hl : LookupSound RangeCheck 11) (hr : RowLookupSound)
    {rows : List.Vector (List.Vector F 12) 16} {Q R : P} (ht : TableOK rows Q R)
    (AX AY : ElemVal 8) (hAX : AX.bnd = lazyOut lazy_h9c68f146) (hAY : AY.bnd = lazyOut lazy_hee995b41)
    (hA : OnCurve (AX.value : Fp) (AY.value : Fp))
    (TX TY : ElemVal 8) (hTX : TX.bnd = reducedC) (hTY : TY.bnd = reducedC)
    (hT : OnCurve (TX.value : Fp) (TY.value : Fp)) {idx : F}
    {k : List.Vector (List.Vector F 8) 2 → Prop}
    (h : RowLookup_12_16 rows idx fun r =>
      AssertDistinctX_8_8_h83dcf683
        (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
          List.Vector.nil) TX.limbs ∧
      Add_8_8_8_8_h8ef7b27b
        (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
          List.Vector.nil)
        (r.get 8 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 9 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 10 ::ᵥ (0 : F) ::ᵥ
          List.Vector.nil) TX.limbs TY.limbs
        fun s => QuadrupleAndAddLazy_8_8_8_8_h4e58d4bc AX.limbs AY.limbs (s.get 0) (s.get 1) 0 k) :
    ∃ i : Fin 16, idx = ((i : ℕ) : F) ∧ ∃ OX OY : ElemVal 8,
      OX.bnd = lazyOut lazy_h9c68f146 ∧ OY.bnd = lazyOut lazy_hc2c2cd77 ∧
      k (OX.limbs ::ᵥ OY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ hO : OnCurve (OX.value : Fp) (OY.value : Fp),
        mkPoint hO = 4 • mkPoint hA + (Ladder.rowPoint i Q R + mkPoint hT) := by
  obtain ⟨i, hi, hk⟩ := hr _ _ _ h
  obtain ⟨X, Y, hXY, hs, hq, hXb, hYb, hxl, hyl, hhs, hlt, hqs, hquart, hpt⟩ := ht i
  rw [hxl, hyl] at hk
  obtain ⟨hg, hadd⟩ := hk
  have dg := distinctX_elem hXb hTX hg
  obtain ⟨SX, SY, hSX, hSY, hk2, cr⟩ := add_h8ef7b27b_sound hl X Y TX TY hXb hYb hTX hTY hadd
  obtain ⟨hS, hSeq⟩ := chord_point hXY hT dg.2.2.2.2 cr.1 cr.2
  simp only [get2_0, get2_1] at hk2
  obtain ⟨OX, OY, hOX, hOY, hk3, L, hLb, dX, dY, μ, ν, iX, c, hlast⟩ :=
    quadAdd_h4e58d4bc_sound hl AX AY SX SY hAX hAY hSX hSY hk2
  obtain ⟨hO, hOeq⟩ := quad_add_correct hA hS c (Or.inr hlast)
  exact ⟨i, hi, OX, OY, hOX, hOY, hk3, hO, by rw [hOeq, hSeq, hpt]⟩

end ZolanaVE.P256
