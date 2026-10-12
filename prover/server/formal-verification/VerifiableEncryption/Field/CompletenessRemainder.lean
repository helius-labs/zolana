import VerifiableEncryption.Field.CompletenessRange

namespace ZolanaVE.Field

theorem piecesOk11_length : ∀ (widths : List ℕ) (ps : List F),
    PiecesOk (LookupCheck RangeCheck 11) 11 widths ps →
      ps.length = (widths.map (nbPieces 11)).sum
  | [], ps, h => by simp only [PiecesOk] at h; simp [h]
  | w :: ws, ps, h => by
    obtain ⟨hlen, hhead, htail⟩ := h
    have ht := piecesOk11_length ws (ps.drop (nbPieces 11 w)) htail
    simp only [List.map_cons, List.sum_cons, List.length_drop] at ht ⊢
    omega

def widths8 : List ℕ := [32, 32, 32, 32, 32, 32, 32, 32]

theorem remainder24_pieces (ps : List F)
    (h : PiecesOk (LookupCheck RangeCheck 11) 11 widths8 ps) :
    ∃ pr : List.Vector F 24, pr.toList = ps ∧
      ∀ i : Fin 8,
        RangeCheck 11 (pr.get ⟨3 * i.val, by omega⟩) ∧
        RangeCheck 11 (pr.get ⟨3 * i.val + 1, by omega⟩) ∧
        RangeCheck 10 (pr.get ⟨3 * i.val + 2, by omega⟩) := by
  have hl : ps.length = 24 := by
    rw [piecesOk11_length _ _ h]
    norm_num [widths8, nbPieces]
  match ps, hl with
  | [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11,
      a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23], _ =>
    simp (config := {decide := true}) only [widths8, PiecesOk, nbPieces, List.take,
      List.drop, List.length_cons, List.length_nil, Nat.reduceAdd, Nat.reduceSub,
      Nat.reduceDiv, ComposeOk, LookupCheck, SmallCheck, if_true, if_false,
      true_and, and_true] at h
    obtain ⟨⟨h0, h1, h2⟩, ⟨h3, h4, h5⟩, ⟨h6, h7, h8⟩, ⟨h9, h10, h11⟩,
      ⟨h12, h13, h14⟩, ⟨h15, h16, h17⟩, ⟨h18, h19, h20⟩, ⟨h21, h22, h23⟩⟩ := h
    refine ⟨vec![a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11,
      a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23], rfl, ?_⟩
    intro i
    fin_cases i
    exacts [⟨h0, h1, h2⟩, ⟨h3, h4, h5⟩, ⟨h6, h7, h8⟩, ⟨h9, h10, h11⟩,
      ⟨h12, h13, h14⟩, ⟨h15, h16, h17⟩, ⟨h18, h19, h20⟩, ⟨h21, h22, h23⟩]

def remainder24_output (pr : List.Vector F 24) : List.Vector F 8 :=
  vec![pr.get 0 + pr.get 1 * 2048 + pr.get 2 * 4194304,
    pr.get 3 + pr.get 4 * 2048 + pr.get 5 * 4194304,
    pr.get 6 + pr.get 7 * 2048 + pr.get 8 * 4194304,
    pr.get 9 + pr.get 10 * 2048 + pr.get 11 * 4194304,
    pr.get 12 + pr.get 13 * 2048 + pr.get 14 * 4194304,
    pr.get 15 + pr.get 16 * 2048 + pr.get 17 * 4194304,
    pr.get 18 + pr.get 19 * 2048 + pr.get 20 * 4194304,
    pr.get 21 + pr.get 22 * 2048 + pr.get 23 * 4194304]

theorem remainder24_output_list (pr : List.Vector F 24) :
    limbsOfPieces 11 widths8 pr.toList = (remainder24_output pr).toList := by
  obtain ⟨ps, hl⟩ := pr
  match ps, hl with
  | [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11,
      a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23], _ =>
    norm_num [limbsOfPieces, widths8, nbPieces, composeValue, evalAt, remainder24_output,
      List.Vector.get, List.Vector.head, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod] <;>
      (repeat' constructor) <;> ring

def outputCheckInputs (L : List.Vector F 24) : List (List F) :=
  [[L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7],
   [L.get 8, L.get 9, L.get 10, L.get 11, L.get 12, L.get 13, L.get 14, L.get 15],
   [L.get 16, L.get 17, L.get 18, L.get 19, L.get 20, L.get 21, L.get 22, L.get 23]]

end ZolanaVE.Field
