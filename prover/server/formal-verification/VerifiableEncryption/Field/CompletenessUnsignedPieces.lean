import VerifiableEncryption.Field.CompletenessEval
import VerifiableEncryption.Field.CompletenessRemainder

/-! Actual unsigned 11/11/10 hint pieces for eight canonical coordinate limbs.
The construction uses mathematical limb values and small-range completeness;
it does not assume an output hint or an extracted gadget succeeds. -/

namespace ZolanaVE.Field

theorem remainder24_output_get (pr : List.Vector F 24) (i : Fin 8) :
    (remainder24_output pr).get i =
      pr.get ⟨3 * i.val, by omega⟩ +
      pr.get ⟨3 * i.val + 1, by omega⟩ * 2048 +
      pr.get ⟨3 * i.val + 2, by omega⟩ * 4194304 := by
  fin_cases i <;> rfl

theorem unsigned8_pieces_complete
    (hr : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (v : ℕ) :
    ∃ pr : List.Vector F 24,
      (∀ i : Fin 8, RangeCheck 11 (pr.get ⟨3 * i.val, by omega⟩) ∧
        RangeCheck 11 (pr.get ⟨3 * i.val + 1, by omega⟩) ∧
        RangeCheck 10 (pr.get ⟨3 * i.val + 2, by omega⟩)) ∧
      ∀ i : Fin 8, (natLimbVector8 v).get i =
        pr.get ⟨3 * i.val, by omega⟩ +
        pr.get ⟨3 * i.val + 1, by omega⟩ * 2048 +
        pr.get ⟨3 * i.val + 2, by omega⟩ * 4194304 := by
  obtain ⟨hp, hv⟩ := widthPieces_complete hr widths8 (natLimbs8 v) (natLimbs8_bounds v)
  obtain ⟨pr, hpr, hrc⟩ := remainder24_pieces _ hp
  rw [← hpr] at hv
  have ho : remainder24_output pr = natLimbVector8 v := by
    apply List.Vector.toList_injective
    rw [← remainder24_output_list, natLimbVector8_list]
    exact hv
  refine ⟨pr, hrc, ?_⟩
  intro i
  rw [← ho]
  exact remainder24_output_get pr i

def jointPieces (px py : List.Vector F 24) : List.Vector F 48 :=
  List.Vector.ofFn (fun j => if hj : j.val < 24 then px.get ⟨j.val, hj⟩
    else py.get ⟨j.val - 24, by omega⟩)

theorem jointPieces_left (px py : List.Vector F 24) (j : Fin 24) :
    (jointPieces px py).get ⟨j.val, by omega⟩ = px.get j := by
  simp [jointPieces, j.2]

theorem jointPieces_right (px py : List.Vector F 24) (j : Fin 24) :
    (jointPieces px py).get ⟨24 + j.val, by omega⟩ = py.get j := by
  simp [jointPieces, show ¬24 + j.val < 24 by omega]

theorem jointPieces_ranges (px py : List.Vector F 24)
    (hx : ∀ i : Fin 8, RangeCheck 11 (px.get ⟨3 * i.val, by omega⟩) ∧
      RangeCheck 11 (px.get ⟨3 * i.val + 1, by omega⟩) ∧
      RangeCheck 10 (px.get ⟨3 * i.val + 2, by omega⟩))
    (hy : ∀ i : Fin 8, RangeCheck 11 (py.get ⟨3 * i.val, by omega⟩) ∧
      RangeCheck 11 (py.get ⟨3 * i.val + 1, by omega⟩) ∧
      RangeCheck 10 (py.get ⟨3 * i.val + 2, by omega⟩)) (i : Fin 16) :
    RangeCheck 11 ((jointPieces px py).get ⟨3 * i.val, by omega⟩) ∧
    RangeCheck 11 ((jointPieces px py).get ⟨3 * i.val + 1, by omega⟩) ∧
    RangeCheck 10 ((jointPieces px py).get ⟨3 * i.val + 2, by omega⟩) := by
  by_cases hi : i.val < 8
  · simpa [jointPieces, show 3 * i.val < 24 by omega,
      show 3 * i.val + 1 < 24 by omega, show 3 * i.val + 2 < 24 by omega] using
      hx ⟨i.val, hi⟩
  · have hn : i.val - 8 < 8 := by omega
    have h0 : 3 * i.val - 24 = 3 * (i.val - 8) := by omega
    have h1 : 3 * i.val + 1 - 24 = 3 * (i.val - 8) + 1 := by omega
    have h2 : 3 * i.val + 2 - 24 = 3 * (i.val - 8) + 2 := by omega
    simpa [jointPieces, show ¬3 * i.val < 24 by omega,
      show ¬3 * i.val + 1 < 24 by omega, show ¬3 * i.val + 2 < 24 by omega,
      h0, h1, h2] using hy ⟨i.val - 8, hn⟩

end ZolanaVE.Field
