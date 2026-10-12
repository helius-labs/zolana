import VerifiableEncryption.Field.CompletenessCarry

/-! Construct production range-check witnesses from explicit small-table
completeness. All 11-bit pieces and recomposition gates are constructed. -/

namespace ZolanaVE.Field

theorem composeOk11_length {rc : ℕ → F → Prop} :
    ∀ (width : ℕ) (ps : List F), ComposeOk rc 11 width ps → ps.length = nbPieces 11 width
  | width, [], h => by
    change width = 0 at h
    subst width
    norm_num [nbPieces]
  | width, p :: ps, h => by
    obtain ⟨hwidth, _, htail⟩ := h
    rw [List.length_cons, composeOk11_length (width - 11) ps htail]
    unfold nbPieces
    omega

def rangePieces (width value : ℕ) : List F :=
  if width = 0 then [] else
    ((value % 2048 : ℕ) : F) :: rangePieces (width - 11) (value / 2048)
termination_by width
decreasing_by omega

theorem smallCheck_complete
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (bits value : ℕ) (hbits : bits ≤ 11) (hvalue : value < 2 ^ bits) :
    SmallCheck RangeCheck bits (value : F) := by
  unfold SmallCheck
  split_ifs with h0 h1
  · subst h0
    have hv : value = 0 := by simpa using hvalue
    simp [hv]
  · subst h1
    have hv : value = 0 ∨ value = 1 := by norm_num at hvalue; omega
    rcases hv with rfl | rfl <;> simp [GatesDef.is_bool]
  · exact hl bits value (by omega) hbits hvalue

theorem rangePieces_length (width value : ℕ) :
    (rangePieces width value).length = nbPieces 11 width := by
  induction width using Nat.strong_induction_on generalizing value with
  | h width ih =>
    rw [rangePieces]
    split_ifs with hw
    · simp [hw, nbPieces]
    · simp only [List.length_cons]
      rw [ih (width - 11) (by omega)]
      unfold nbPieces
      omega

theorem rangePieces_complete
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (width value : ℕ) (hvalue : value < 2 ^ width) :
    ComposeOk (SmallCheck RangeCheck) 11 width (rangePieces width value) ∧
      composeValue 11 (rangePieces width value) = (value : F) := by
  induction width using Nat.strong_induction_on generalizing value with
  | h width ih =>
    rw [rangePieces]
    split_ifs with hw
    · have hv : value = 0 := by simpa [hw] using hvalue
      simp [ComposeOk, composeValue, evalAt, hv, hw]
    · have hwpos : 0 < width := by omega
      have hlow : value % 2048 < 2 ^ min 11 width := by
        by_cases hwidth : width ≤ 11
        · rw [min_eq_right hwidth]
          exact lt_of_le_of_lt (Nat.mod_le _ _) hvalue
        · rw [min_eq_left (by omega)]
          exact Nat.mod_lt _ (by norm_num)
      have hhigh : value / 2048 < 2 ^ (width - 11) := by
        by_cases hwidth : width ≤ 11
        · have hp : 2 ^ width ≤ (2048 : ℕ) := by
            have hp := Nat.pow_le_pow_right (by norm_num : 1 ≤ (2 : ℕ)) hwidth
            norm_num at hp
            exact hp
          have hv : value / 2048 = 0 := Nat.div_eq_of_lt (lt_of_lt_of_le hvalue hp)
          simp [hv]
        · have hp : 2 ^ width = (2048 : ℕ) * 2 ^ (width - 11) := by
            rw [show width = 11 + (width - 11) by omega, pow_add]
            norm_num
          rw [hp] at hvalue
          exact (Nat.div_lt_iff_lt_mul (by norm_num)).mpr (by simpa [mul_comm] using hvalue)
      obtain ⟨hrest, hcompose⟩ := ih (width - 11) (by omega) (value / 2048) hhigh
      refine ⟨⟨hwpos, smallCheck_complete hl _ _ (min_le_left _ _) hlow, hrest⟩, ?_⟩
      simp only [composeValue, evalAt_cons]
      change ((value % 2048 : ℕ) : F) + (2 : F) ^ 11 *
        composeValue 11 (rangePieces (width - 11) (value / 2048)) = (value : F)
      rw [hcompose]
      have hv := congrArg (fun n : ℕ => (n : F)) (Nat.mod_add_div value 2048)
      norm_num at hv ⊢
      push_cast at hv
      exact hv

/-- Completeness of the exact generic production LookupCheck layout at all
supported widths follows from small-table completeness; no range witnesses
or successful decomposition hints are assumed. -/
theorem lookupCheck_complete
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F)) :
    RangeComplete253 (LookupCheck RangeCheck 11) := by
  intro width value hwidth hvalue
  unfold LookupCheck
  split_ifs with hw
  · exact smallCheck_complete hl width value hw hvalue
  · obtain ⟨hpieces, hcompose⟩ := rangePieces_complete hl width value hvalue
    exact ⟨rangePieces width value, hpieces, hcompose.symm⟩

def widthPieces : List ℕ → List ℕ → List F
  | [], _ => []
  | _, [] => []
  | width :: widths, value :: values => rangePieces width value ++ widthPieces widths values

theorem composeOk_lookup_of_small : ∀ (width : ℕ) (ps : List F),
    ComposeOk (SmallCheck RangeCheck) 11 width ps →
      ComposeOk (LookupCheck RangeCheck 11) 11 width ps
  | width, [], h => h
  | width, p :: ps, h => by
    refine ⟨h.1, ?_, composeOk_lookup_of_small (width - 11) ps h.2.2⟩
    unfold LookupCheck
    rw [if_pos (min_le_left _ _)]
    exact h.2.1

/-- Construct every hinted limb piece, including its exact piece count,
and prove that fromPieces returns the chosen integer limbs. -/
theorem widthPieces_complete
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F)) :
    ∀ (widths values : List ℕ), List.Forall₂ (fun value width => value < 2 ^ width) values widths →
      PiecesOk (LookupCheck RangeCheck 11) 11 widths (widthPieces widths values) ∧
      limbsOfPieces 11 widths (widthPieces widths values) = values.map (Nat.cast : ℕ → F)
  | [], [], h => by simp [widthPieces, PiecesOk, limbsOfPieces]
  | [], _ :: _, h => by cases h
  | _ :: _, [], h => by cases h
  | width :: widths, value :: values, h => by
    cases h with
    | cons hvalue htail =>
      obtain ⟨hrest, hlimbs⟩ := widthPieces_complete hl widths values htail
      obtain ⟨hpieces, hcompose⟩ := rangePieces_complete hl width value hvalue
      have htake : (rangePieces width value ++ widthPieces widths values).take (nbPieces 11 width) =
          rangePieces width value := by
        rw [← rangePieces_length width value]
        simp
      have hdrop : (rangePieces width value ++ widthPieces widths values).drop (nbPieces 11 width) =
          widthPieces widths values := by
        rw [← rangePieces_length width value]
        simp
      have hcomposeRC : ComposeOk (LookupCheck RangeCheck 11) 11 width (rangePieces width value) := by
        exact composeOk_lookup_of_small width _ hpieces
      simp only [widthPieces, PiecesOk, limbsOfPieces, htake, hdrop]
      refine ⟨⟨?_, hcomposeRC, hrest⟩, ?_⟩
      · rw [List.length_append, rangePieces_length]
        omega
      · rw [hcompose, hlimbs]
        rfl

end ZolanaVE.Field
