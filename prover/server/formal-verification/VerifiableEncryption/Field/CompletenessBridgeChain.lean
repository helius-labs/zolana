import VerifiableEncryption.Field.CompletenessBridge
import VerifiableEncryption.Field.CompletenessGeneratedChain_69

/-! Second fixed-base slope reverse interface to the checked actual primitive. -/

namespace ZolanaVE.Field
open ZolanaVE.EmcurveChecks

theorem lookupCheck_seven_pieces (last : ℕ) (hlast : 2 ≤ last ∧ last ≤ 11) (value : F)
    (h : LookupCheck RangeCheck 11 (66 + last) value) :
    ∃ ps : List.Vector F 7,
      RangeCheck 11 (ps.get 0) ∧ RangeCheck 11 (ps.get 1) ∧
      RangeCheck 11 (ps.get 2) ∧ RangeCheck 11 (ps.get 3) ∧
      RangeCheck 11 (ps.get 4) ∧ RangeCheck 11 (ps.get 5) ∧
      RangeCheck last (ps.get 6) ∧ value = composeValue 11 ps.toList := by
  unfold LookupCheck at h
  rw [if_neg (by omega)] at h
  obtain ⟨ps, hp, hv⟩ := h
  have hlen : ps.length = 7 := by
    rw [composeOk11_length _ _ hp]
    unfold nbPieces
    omega
  match ps, hlen with
  | [a, b, c, d, e, f, g], _ =>
    have hr : RangeCheck 11 a ∧ RangeCheck 11 b ∧ RangeCheck 11 c ∧
        RangeCheck 11 d ∧ RangeCheck 11 e ∧ RangeCheck 11 f ∧ RangeCheck last g := by
      obtain ⟨hlow, hhigh⟩ := hlast
      interval_cases last <;> norm_num [ComposeOk, SmallCheck] at hp ⊢ <;> exact hp
    exact ⟨vec![a, b, c, d, e, f, g], hr.1, hr.2.1, hr.2.2.1,
      hr.2.2.2.1, hr.2.2.2.2.1, hr.2.2.2.2.2.1, hr.2.2.2.2.2.2, hv⟩

def chainCheckInputs48 (L : List.Vector F 48) : List (List F) :=
  [[L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7],
   [L.get 8, L.get 9, L.get 10, L.get 11, L.get 12, L.get 13, L.get 14, L.get 15],
   [L.get 16, L.get 17, L.get 18, L.get 19, L.get 20, L.get 21, L.get 22, L.get 23],
   [L.get 24, L.get 25, L.get 26, L.get 27, L.get 28, L.get 29, L.get 30, L.get 31],
   [L.get 32, L.get 33, L.get 34, L.get 35, L.get 36, L.get 37, L.get 38, L.get 39],
   [L.get 40, L.get 41, L.get 42, L.get 43, L.get 44, L.get 45, L.get 46, L.get 47]]

theorem secondChainSlope_check_of_model (L : List.Vector F 48)
    (h : CheckPolynomial.circuit basis cert_hd6f972c2 (chainCheckInputs48 L)
      (LookupCheck RangeCheck 11) (fun _ => True)) :
    CheckPolynomial_48_hd6f972c2 L :=
  CheckPolynomial_48_hd6f972c2_of_model L h

end ZolanaVE.Field
