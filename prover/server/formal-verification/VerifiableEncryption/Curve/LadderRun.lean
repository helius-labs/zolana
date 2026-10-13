import VerifiableEncryption.Curve.LadderTable

/-!
The ladder's uniform middle steps as one recursive predicate, in the
extracted form, so a run of them is discharged by induction.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-- Middle ladder steps in the extracted form: the selector gates, the row
lookup, and the doubling-aware quadruple-and-add, threaded through the
accumulator pair. Each step names its selector bits `(n, d, n', d')` with
`idx = n + 2d + 4n' + 8d'`. -/
def LadderRun (rows : List.Vector (List.Vector F 12) 16) (g : List.Vector F 259) :
    List (Fin 259 × Fin 259 × Fin 259 × Fin 259) → List.Vector (List.Vector F 8) 2 →
      (List.Vector (List.Vector F 8) 2 → Prop) → Prop
  | [], A, K => K A
  | (a, c, d, e) :: ss, A, K =>
    ∃ g1, g1 = Gates.mul (g.get c) (2 : F) ∧
    ∃ g2, g2 = Gates.mul (g.get d) (4 : F) ∧
    ∃ g3, g3 = Gates.mul (g.get e) (8 : F) ∧
    ∃ gi, gi = Gates.add (Gates.add (Gates.add (g.get a) g1) g2) g3 ∧
    RowLookup_12_16 rows gi fun r =>
      QuadrupleAndAddLazy_8_8_8_8_haf2b5bed (A.get 0) (A.get 1)
        (r.get 0 ::ᵥ r.get 1 ::ᵥ r.get 2 ::ᵥ r.get 3 ::ᵥ r.get 4 ::ᵥ r.get 5 ::ᵥ r.get 6 ::ᵥ r.get 7 ::ᵥ
          List.Vector.nil)
        (r.get 8 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 9 ::ᵥ (0 : F) ::ᵥ (0 : F) ::ᵥ r.get 10 ::ᵥ (0 : F) ::ᵥ
          List.Vector.nil) (r.get 11) fun B => LadderRun rows g ss B K

/-- The `Q` coefficient after a run: `a ↦ 4a + digQ`. -/
def runQ (g : List.Vector F 259) (ss : List (Fin 259 × Fin 259 × Fin 259 × Fin 259)) (a : ℤ) : ℤ :=
  ss.foldl (fun a s => 4 * a + (2 * (2 * bitI g s.1 + bitI g s.2.2.1) - 3)) a

/-- The `R` coefficient after a run: `c ↦ 4c + digR`. -/
def runR (g : List.Vector F 259) (ss : List (Fin 259 × Fin 259 × Fin 259 × Fin 259)) (c : ℤ) : ℤ :=
  ss.foldl (fun c s => 4 * c + (2 * (2 * bitI g s.2.1 + bitI g s.2.2.2) - 3)) c

theorem ladderRun_sound (hl : LookupSound RangeCheck 11) (hr : RowLookupSound)
    {rows : List.Vector (List.Vector F 12) 16} {Q R : P} (ht : TableOK rows Q R)
    {g : List.Vector F 259} (hb : AllBits g) :
    ∀ (ss : List (Fin 259 × Fin 259 × Fin 259 × Fin 259)) (AX AY : ElemVal 8),
      AX.bnd = lazyOut lazy_h9c68f146 → AY.bnd = lazyOut lazy_hee995b41 →
      ∀ (hA : OnCurve (AX.value : Fp) (AY.value : Fp)) (a c : ℤ), mkPoint hA = a • Q + c • R →
      ∀ {K : List.Vector (List.Vector F 8) 2 → Prop},
      LadderRun rows g ss (AX.limbs ::ᵥ AY.limbs ::ᵥ List.Vector.nil) K →
      ∃ OX OY : ElemVal 8, OX.bnd = lazyOut lazy_h9c68f146 ∧ OY.bnd = lazyOut lazy_hee995b41 ∧
        K (OX.limbs ::ᵥ OY.limbs ::ᵥ List.Vector.nil) ∧
        ∃ hO : OnCurve (OX.value : Fp) (OY.value : Fp), mkPoint hO = runQ g ss a • Q + runR g ss c • R := by
  intro ss
  induction ss with
  | nil =>
    intro AX AY hAX hAY hA a c hinv K h
    exact ⟨AX, AY, hAX, hAY, h, hA, hinv⟩
  | cons s ss ih =>
    obtain ⟨a', c', d', e'⟩ := s
    intro AX AY hAX hAY hA a c hinv K h
    obtain ⟨_, rfl, _, rfl, _, rfl, _, rfl, h⟩ := h
    simp only [get2_0, get2_1] at h
    obtain ⟨i, hi, OX, OY, hOX, hOY, hk, hO, hOeq⟩ := ladder_step_haf2b5bed hl hr ht AX AY hAX hAY hA h
    have hd := sel_digits hb (a := a') (c := c') (d := d') (e := e') a'.2 c'.2 d'.2 e'.2 (by
      simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, vget_getD] at hi
      exact hi)
    exact ih OX OY hOX hOY hO _ _ (step_inv hinv hOeq hd) hk

end ZolanaVE.P256
