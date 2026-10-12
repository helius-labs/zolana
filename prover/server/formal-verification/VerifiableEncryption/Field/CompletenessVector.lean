import VerifiableEncryption.Field.CompletenessRange

/-!
Recover the exact extracted range-hint vector from the constructive lookup
model. Every piece retains its SmallCheck, including a final Boolean piece.
This source has not been elaborated or evaluated.
-/

namespace ZolanaVE.Field

theorem composeOk_get {rc : ℕ → F → Prop} (pb : ℕ) :
    ∀ (width : ℕ) (ps : List F), ComposeOk rc pb width ps →
      ∀ i : Fin ps.length, rc (min pb (width - pb * i.val)) (ps.get i)
  | width, [], _, i => Fin.elim0 i
  | width, p :: ps, h, i => by
    obtain ⟨_, hp, htail⟩ := h
    cases i using Fin.cases with
    | zero => simpa using hp
    | succ i =>
      have hr := composeOk_get pb (width - pb) ps htail i
      have hwidth : width - pb - pb * i.val = width - pb * (i.val + 1) := by
        rw [Nat.mul_add]
        omega
      simpa only [List.length_cons, List.get_cons_succ', Fin.val_succ, hwidth] using hr

theorem lookupCheck_vector_pieces (width n : ℕ) (hwide : 11 < width)
    (hcount : nbPieces 11 width = n) (value : F)
    (h : LookupCheck RangeCheck 11 width value) :
    ∃ ps : List.Vector F n,
      (∀ i : Fin n, SmallCheck RangeCheck (min 11 (width - 11 * i.val)) (ps.get i)) ∧
      value = composeValue 11 ps.toList := by
  unfold LookupCheck at h
  rw [if_neg (by omega)] at h
  obtain ⟨ps, hp, hv⟩ := h
  have hlen : ps.length = n := (composeOk11_length width ps hp).trans hcount
  refine ⟨⟨ps, hlen⟩, ?_, hv⟩
  intro i
  exact composeOk_get 11 width ps hp ⟨i.val, by omega⟩

end ZolanaVE.Field
