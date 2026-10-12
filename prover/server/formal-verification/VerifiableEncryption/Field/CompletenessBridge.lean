import VerifiableEncryption.Field.CompletenessRange
import VerifiableEncryption.Field.CompletenessGeneratedChain_17

/-! Fixed-base reverse interface with all native obligations supplied by the
checked generated primitive. The four-piece range helper remains explicit. -/

namespace ZolanaVE.Field
open ZolanaVE.EmcurveChecks

/-- Four concrete range pieces, with the actual final-piece width. -/
theorem lookupCheck_four_pieces (last : ℕ) (hlast : 2 ≤ last ∧ last ≤ 11) (value : F)
    (h : LookupCheck RangeCheck 11 (33 + last) value) :
    ∃ ps : List.Vector F 4,
      RangeCheck 11 (ps.get 0) ∧ RangeCheck 11 (ps.get 1) ∧
      RangeCheck 11 (ps.get 2) ∧ RangeCheck last (ps.get 3) ∧
      value = composeValue 11 ps.toList := by
  unfold LookupCheck at h
  rw [if_neg (by omega)] at h
  obtain ⟨ps, hp, hv⟩ := h
  have hlen : ps.length = 4 := by
    rw [composeOk11_length _ _ hp]
    unfold nbPieces
    omega
  match ps, hlen with
  | [a, b, c, d], _ =>
    have hp' : RangeCheck 11 a ∧ RangeCheck 11 b ∧
        RangeCheck 11 c ∧ RangeCheck last d := by
      have hmin0 : min 11 (33 + last) = 11 := min_eq_left (by omega)
      have hmin1 : min 11 (22 + last) = 11 := min_eq_left (by omega)
      have hmin2 : min 11 (11 + last) = 11 := min_eq_left (by omega)
      have hsub0 : 33 + last - 11 = 22 + last := by omega
      have hsub1 : 22 + last - 11 = 11 + last := by omega
      have hsub2 : 11 + last - 11 = last := by omega
      have hsub3 : last - 11 = 0 := by omega
      simpa [ComposeOk, SmallCheck, hmin0, hmin1, hmin2, hsub0,
        hsub1, hsub2, hsub3, min_eq_right hlast.2,
        show last ≠ 0 from by omega, show last ≠ 1 from by omega,
        show 0 < last from by omega] using hp
    exact ⟨vec![a, b, c, d], hp'.1, hp'.2.1, hp'.2.2.1, hp'.2.2.2, hv⟩

def chainCheckInputs (L : List.Vector F 32) : List (List F) :=
  [[L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7],
   [L.get 8, L.get 9, L.get 10, L.get 11, L.get 12, L.get 13, L.get 14, L.get 15],
   [L.get 16, L.get 17, L.get 18, L.get 19, L.get 20, L.get 21, L.get 22, L.get 23],
   [L.get 24, L.get 25, L.get 26, L.get 27, L.get 28, L.get 29, L.get 30, L.get 31]]

theorem chainSlope_check_of_model (L : List.Vector F 32)
    (h : CheckPolynomial.circuit basis cert_hb838cae4 (chainCheckInputs L)
      (LookupCheck RangeCheck 11) (fun _ => True)) :
    CheckPolynomial_32_hb838cae4 L :=
  CheckPolynomial_32_hb838cae4_of_model L h

end ZolanaVE.Field
