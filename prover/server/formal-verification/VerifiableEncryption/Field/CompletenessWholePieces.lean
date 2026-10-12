import VerifiableEncryption.Field.CompletenessRemainder
import VerifiableEncryption.Field.ExMirror

/-! Recover the exact quotient-piece hints of the three nonfolded scalar
checks. These statements retain every emitted range obligation. -/

namespace ZolanaVE.Field

theorem whole_ex_eval_add (env : ℕ → F) (a b : Ex) :
    (Ex.add a b).eval env = a.eval env + b.eval env := rfl

theorem whole_ex_eval_mul (env : ℕ → F) (a b : Ex) :
    (Ex.mul a b).eval env = a.eval env * b.eval env := rfl

theorem whole_ex_eval_lit (env : ℕ → F) (n : ℕ) :
    (Ex.lit n).eval env = (n : F) := rfl

theorem whole_ex_eval_zero (env : ℕ → F) : Ex.zero.eval env = 0 := rfl

/-- Preserve residual expressions as opaque arguments while evaluating the
outer carry operations. This avoids expanding the entire nonfolded AST. -/
theorem whole_eCarry_eval (env : ℕ → F) (pres : ℕ → Ex) (g : CarryGroup) (pc : Ex) :
    (eCarry pres g pc).eval env =
      (sumRange (g.stop - g.start) (fun j => (pres (g.start + j)).eval env * pow32 j) +
        pc.eval env) * (g.inv : F) := by
  dsimp only [eCarry]
  rw [whole_ex_eval_mul, whole_ex_eval_add, whole_ex_eval_lit, eval_eSumRange]
  simp only [whole_ex_eval_mul, eval_ePow32]

theorem quotient1_pieces (ps : List F)
    (h : PiecesOk (LookupCheck RangeCheck 11) 11 [2] ps) :
    ∃ pq : List.Vector F 1, pq.toList = ps ∧ RangeCheck 2 (pq.get 0) := by
  have hl : ps.length = 1 := by
    rw [piecesOk11_length _ _ h]
    norm_num [nbPieces]
  match ps, hl with
  | [q0], _ =>
    simp (config := {decide := true}) only [PiecesOk, nbPieces, List.take,
      List.drop, List.length_cons, List.length_nil, Nat.reduceAdd, Nat.reduceSub,
      Nat.reduceDiv, ComposeOk, LookupCheck, SmallCheck, if_true, if_false,
      true_and, and_true] at h
    exact ⟨vec![q0], rfl, h⟩

def quotient13Widths : List ℕ := [32, 32, 32, 32, 3]

def quotient13PieceWidth (i : Fin 13) : ℕ :=
  [11, 11, 10, 11, 11, 10, 11, 11, 10, 11, 11, 10, 3].getD i.val 0

theorem quotient13_pieces (ps : List F)
    (h : PiecesOk (LookupCheck RangeCheck 11) 11 quotient13Widths ps) :
    ∃ pq : List.Vector F 13, pq.toList = ps ∧
      ∀ i : Fin 13, RangeCheck (quotient13PieceWidth i) (pq.get i) := by
  have hl : ps.length = 13 := by
    rw [piecesOk11_length _ _ h]
    norm_num [quotient13Widths, nbPieces]
  match ps, hl with
  | [q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12], _ =>
    simp (config := {decide := true}) only [quotient13Widths, PiecesOk, nbPieces,
      List.take, List.drop, List.length_cons, List.length_nil, Nat.reduceAdd,
      Nat.reduceSub, Nat.reduceDiv, ComposeOk, LookupCheck, SmallCheck, if_true,
      if_false, true_and, and_true] at h
    obtain ⟨⟨h0, h1, h2⟩, ⟨h3, h4, h5⟩, ⟨h6, h7, h8⟩,
      ⟨h9, h10, h11⟩, h12⟩ := h
    refine ⟨vec![q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12], rfl, ?_⟩
    intro i
    fin_cases i
    exacts [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12]


/-- Whole checks ignore the folded quotient argument; rewriting this before
native expression comparison avoids evaluating that unused field inverse. -/
theorem whole_residual_nonfold (b : BasisParams) (c : PlainCheckParams)
    (xs : List (List F)) (r ql : List F) (kq : F) (hf : c.fold = false) :
    CheckPolynomial.residual b c xs r ql kq =
      CheckPolynomial.residual b c xs r ql 0 := by
  funext pos
  simp only [CheckPolynomial.residual, hf, Bool.false_eq_true, ite_false]

end ZolanaVE.Field
