import VerifiableEncryption.Field.CompletenessEval

/-!
Whole-value (nonfolded) emulated-field witness construction. The quotient
capacity uses the asymmetric input-value intervals, including offset-zero
scalar canonicalization. No canonical-input restriction or hint-success
premise is introduced. The remaining capacities are static certificate data.
The generic constructor and its wrappers passed the pinned Lean kernel check.
-/

namespace ZolanaVE.Field

/-- A production radix-32 layout with `n` full limbs and one final limb. -/
def wholeQuotientWidths : ℕ → ℕ → List ℕ
  | 0, top => [top]
  | n + 1, top => 32 :: wholeQuotientWidths n top

/-- Last limb is the remaining integer, rather than a truncated residue. -/
def wholeQuotientLimbs : ℕ → ℕ → List ℕ
  | 0, value => [value]
  | n + 1, value => value % 2 ^ 32 :: wholeQuotientLimbs n (value / 2 ^ 32)

theorem wholeQuotientLimbs_length (n value : ℕ) :
    (wholeQuotientLimbs n value).length = n + 1 := by
  induction n generalizing value with
  | zero => simp [wholeQuotientLimbs]
  | succ n ih => simp [wholeQuotientLimbs, ih]

theorem wholeQuotientWidths_length (n top : ℕ) :
    (wholeQuotientWidths n top).length = n + 1 := by
  induction n with
  | zero => simp [wholeQuotientWidths]
  | succ n ih => simp [wholeQuotientWidths, ih]

theorem wholeQuotientLimbs_bounds (n top value : ℕ)
    (hv : value < 2 ^ (32 * n + top)) :
    List.Forall₂ (fun value width => value < 2 ^ width)
      (wholeQuotientLimbs n value) (wholeQuotientWidths n top) := by
  induction n generalizing value with
  | zero => simpa [wholeQuotientLimbs, wholeQuotientWidths] using
      (List.Forall₂.cons hv List.Forall₂.nil)
  | succ n ih =>
    refine .cons (Nat.mod_lt _ (by norm_num)) (ih _ ?_)
    apply (Nat.div_lt_iff_lt_mul (by norm_num : 0 < 2 ^ 32)).mpr
    have he : 32 * (n + 1) + top = (32 * n + top) + 32 := by omega
    simpa [he, pow_add] using hv

theorem wholeQuotientLimbs_recompose (n value : ℕ) :
    recompose ((wholeQuotientLimbs n value).map (Nat.cast : ℕ → ℤ)) = value := by
  induction n generalizing value with
  | zero => simp [wholeQuotientLimbs, recompose_cons, recompose, evalAt]
  | succ n ih =>
    simp only [wholeQuotientLimbs, List.map_cons, recompose_cons, ih]
    have he := congrArg (fun v : ℕ => (v : ℤ)) (Nat.mod_add_div value (2 ^ 32))
    push_cast at he
    exact he

def wholeExpressionLower (c : PlainCheckParams) : ℤ :=
  (c.terms.map fun t =>
    (termRange (fun f => ((c.elem f).vlo, (c.elem f).vhi)) t.coef t.factors).1).sum

def wholeExpressionUpper (c : PlainCheckParams) : ℤ :=
  (c.terms.map fun t =>
    (termRange (fun f => ((c.elem f).vlo, (c.elem f).vhi)) t.coef t.factors).2).sum

theorem wholeExpression_bounds (c : PlainCheckParams)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems) :
    wholeExpressionLower c ≤ c.exprValue (values es) ∧
      c.exprValue (values es) ≤ wholeExpressionUpper c :=
  exprValue_bounds hb

/-- Integer floor division is monotone for a positive emulated modulus. -/
theorem whole_ediv_mono (a b m : ℤ) (hm : 0 < m) (hab : a ≤ b) :
    a / m ≤ b / m := by
  have ha := Int.emod_add_ediv a m
  have hb := Int.emod_add_ediv b m
  have har := Int.emod_nonneg a (ne_of_gt hm)
  have hbr := Int.emod_lt_of_pos b hm
  by_contra h
  have hq : b / m + 1 ≤ a / m := by omega
  nlinarith

/-- Nonfolded Eval/AssertZero constructor. Quotient floor bounds and the
radix layout are static facts about the certificate and its input intervals.
The only input-dependent AssertZero premise is its mathematical specification
`E % m = 0`; neither circuit acceptance nor a successful hint is assumed. -/
theorem wholeCheck_complete (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (hfold : c.fold = false) (hpb : c.pieceBits = 11)
    (hwidths : c.resultWidths = limbWidths8) (hmWidth : c.m < 2 ^ 256)
    (full top : ℕ)
    (hqw : c.quotientWidths = wholeQuotientWidths full top)
    (hqb : c.quotientBits = 32 * full + top)
    (hqLower : 0 ≤ wholeExpressionLower c / (c.m : ℤ) + c.offset)
    (hqUpper : wholeExpressionUpper c / (c.m : ℤ) + c.offset < 2 ^ c.quotientBits)
    (hcapacity : CarryCapacity (c.residualBound b) c.positions c.carryPositions c.groups 0 none)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    (hnoResultZero : c.withResult = false → c.exprValue (values es) % (c.m : ℤ) = 0)
    (k : Option (List F) → Prop)
    (hk : k (if c.withResult then
      some ((natLimbs8 ((c.exprValue (values es) % (c.m : ℤ)).toNat)).map
        (Nat.cast : ℕ → F)) else none)) :
    CheckPolynomial.circuit b c (limbLists es) (LookupCheck RangeCheck 11) k := by
  have hpf := plainFacts hc
  have hbf := basisFacts hbs
  have hsf := shapeFacts hpf.shape
  obtain ⟨_, hol, hor, _, hdeg, hpos, hsize⟩ := hpf.general hfold
  let E : ℤ := c.exprValue (values es)
  let R : ℤ := E % (c.m : ℤ)
  let K : ℤ := E / (c.m : ℤ)
  let Q : ℕ := (K + c.offset).toNat
  let ql := wholeQuotientLimbs full Q
  let rl := if c.withResult then natLimbs8 R.toNat else []
  let Ml := c.modulusLimbs.map (Nat.cast : ℕ → ℤ)
  let Kl := List.zipWith (fun a b : ℤ => a - b)
    (ql.map (Nat.cast : ℕ → ℤ)) (c.offsetLimbs.map (Nat.cast : ℕ → ℤ))
  let Res := fun pos => foldedInt b c.toPolyShape es pos -
    ((rl.getD pos 0 : ℕ) : ℤ) - (polyMul Kl Ml).getD pos 0
  have hm : (0 : ℤ) < c.m := by exact_mod_cast hpf.m_pos
  have hEbounds := wholeExpression_bounds c es hb
  have hKrange : 0 ≤ K + c.offset ∧ K + c.offset < 2 ^ c.quotientBits := by
    have hlo := whole_ediv_mono _ _ _ hm hEbounds.1
    have hhi := whole_ediv_mono _ _ _ hm hEbounds.2
    dsimp [K, E]
    constructor <;> linarith
  have hQcast : (Q : ℤ) = K + c.offset := Int.toNat_of_nonneg hKrange.1
  have hQwidth : Q < 2 ^ (32 * full + top) := by
    have he : (Q : ℤ) < 2 ^ (32 * full + top) := by
      rw [hQcast, ← hqb]; exact hKrange.2
    exact_mod_cast he
  have hqlBound : List.Forall₂ (fun value width => value < 2 ^ width) ql c.quotientWidths := by
    rw [hqw]; exact wholeQuotientLimbs_bounds full top Q hQwidth
  have hqLen : ql.length = c.quotientWidths.length := hqlBound.length_eq
  have hKlLen : Kl.length = ql.length := by simp [Kl, hqLen, hol]
  have hKlCapacity : Kl.length ≤ c.quotientLimbCount := by
    simp [PlainCheckParams.quotientLimbCount, hfold, hKlLen, hqLen]
  have hKlGet : ∀ a < ql.length,
      Kl.getD a 0 = ((ql.getD a 0 : ℕ) : ℤ) - c.offsetLimbs.getD a 0 := by
    intro a ha
    rw [getD_zipWith_sub _ _ _ (by simpa using ha) (by simp [hqLen, hol])]
    simp only [getD_map_natCast]
  have hKlRec : recompose Kl = K := by
    rw [recompose_zipWith_sub _ _ (by simp [hqLen, hol]), hor]
    change recompose ((wholeQuotientLimbs full Q).map (Nat.cast : ℕ → ℤ)) - c.offset = K
    rw [wholeQuotientLimbs_recompose, hQcast]
    ring
  have hKlBound : ∀ a, |Kl.getD a 0| ≤ c.quotientLimbBound a := by
    intro a
    simp only [PlainCheckParams.quotientLimbBound, hfold, Bool.false_eq_true, if_false]
    by_cases ha : a < ql.length
    · rw [hKlGet a ha]
      have hqa := natBounds_getD _ _ hqlBound a
      have hqai : ((ql.getD a 0 : ℕ) : ℤ) < 2 ^ (c.quotientWidths.getD a 0) := by
        exact_mod_cast hqa
      apply abs_le_shiftedBound
      · have := Int.natCast_nonneg (ql.getD a 0); linarith
      · linarith
    · rw [getD_eq_zero_of_le (by omega), abs_zero]
      exact shiftedBound_nonneg _ _
  have hR0 : 0 ≤ R := Int.emod_nonneg _ (ne_of_gt hm)
  have hRlt : R < c.m := Int.emod_lt_of_pos _ hm
  have hRn : ((R.toNat : ℕ) : ℤ) = R := Int.toNat_of_nonneg hR0
  have hRWidth : R.toNat < 2 ^ 256 := by
    have hmW : (c.m : ℤ) < 2 ^ 256 := by exact_mod_cast hmWidth
    omega
  have hRZero : c.withResult = false → R = 0 := hnoResultZero
  have hRrec : recompose (rl.map (Nat.cast : ℕ → ℤ)) = R := by
    cases hw : c.withResult
    · simp [rl, hw, hRZero hw, recompose, evalAt]
    · simp only [rl, hw, if_true]
      rw [natLimbs8_recompose R.toNat hRWidth, hRn]
  have hrlBound : List.Forall₂ (fun value width => value < 2 ^ width) rl
      (if c.withResult then c.resultWidths else []) := by
    cases hw : c.withResult
    · simp [rl, hw]
    · simpa [rl, hw, hwidths] using natLimbs8_bounds R.toNat
  have hrlLen : rl.length ≤ limbCount := by
    cases hw : c.withResult <;> simp [rl, hw, natLimbs8, limbCount]
  have hResBound : ∀ pos, |Res pos| ≤ c.residualBound b pos := by
    intro pos
    have hA := foldedInt_bound hb hsf pos
    have hR := natBounds_getD _ _ hrlBound pos
    have hRi : |((rl.getD pos 0 : ℕ) : ℤ)| ≤
        if c.withResult then 2 ^ (c.resultWidths.getD pos 0) - 1 else 0 := by
      cases hw : c.withResult
      · simp [rl, hw]
      · simp only [hw, if_true]
        rw [abs_of_nonneg (Int.natCast_nonneg _)]
        have hInt : ((rl.getD pos 0 : ℕ) : ℤ) < (2 : ℤ) ^ (c.resultWidths.getD pos 0) := by
          simp only [hw, if_true] at hR
          exact_mod_cast hR
        omega
    have hQ := quotientTerm_bound c hpf.limbs_len hKlCapacity hKlBound pos
    dsimp [Res]
    calc
      |foldedInt b c.toPolyShape es pos - ((rl.getD pos 0 : ℕ) : ℤ) -
          (polyMul Kl Ml).getD pos 0| ≤
          |foldedInt b c.toPolyShape es pos| + |((rl.getD pos 0 : ℕ) : ℤ)| +
          |(polyMul Kl Ml).getD pos 0| :=
        (abs_sub _ _).trans (add_le_add_right (abs_sub _ _) _)
      _ ≤ _ := add_le_add (add_le_add hA hRi) hQ
  have hQNative : ∀ pos,
      ((polyMul Kl Ml).getD pos 0 : F) =
        sumRange (ql.map (Nat.cast : ℕ → F)).length (fun a =>
          if a ≤ pos ∧ pos - a < limbCount then
            ((ql.map (Nat.cast : ℕ → F)).getD a 0 - (c.offsetLimbs.getD a 0 : F)) *
              CheckPolynomial.modLimb c (pos - a) else 0) := by
    intro pos
    rw [getD_polyMul, hKlLen, intCast_sumRange]
    simp only [List.length_map, sumRange_eq]
    apply Finset.sum_congr rfl
    intro a ha
    have ha' : a < ql.length := Finset.mem_range.mp ha
    have hm := modulusLimbs_getD c hpf.limbs_len (pos - a)
    by_cases hap : a ≤ pos
    · by_cases hlt : pos - a < limbCount
      · simp only [hap, hlt, and_self, if_true, Int.cast_mul, hKlGet a ha',
          Int.cast_sub, Int.cast_natCast, getD_natCast_F]
        rw [hm]; simp [hlt]
      · simp only [hap, hlt, and_false, if_false, if_true, Int.cast_mul]
        rw [hm]; simp [hlt]
    · simp [hap]
  have hResNative : ∀ pos, (Res pos : F) = CheckPolynomial.residual b c (limbLists es)
      (rl.map (Nat.cast : ℕ → F)) (ql.map (Nat.cast : ℕ → F)) (K : F) pos := by
    intro pos
    dsimp [Res]
    simp only [Int.cast_sub, Int.cast_natCast, CheckPolynomial.residual,
      hfold, Bool.false_eq_true, if_false, ← exprVal_eq hbf hb hsf, getD_natCast_F]
    rw [hQNative]
    simp only [getD_natCast_F]
  have hRsum : sumRange c.positions (fun i => ((rl.getD i 0 : ℕ) : ℤ) * 2 ^ (32 * i)) = R := by
    have hs := recompose_eq_sumRange (row := rl.map (Nat.cast : ℕ → ℤ))
      (n := c.positions) (by simp only [List.length_map]; omega)
    rw [hRrec] at hs
    simpa only [getD_map_natCast] using hs.symm
  have hQsum : sumRange c.positions (fun i => (polyMul Kl Ml).getD i 0 * 2 ^ (32 * i)) =
      K * c.m := by
    have hlen : (polyMul Kl Ml).length ≤ c.positions := by
      refine (length_polyMul_le _ _ (by simp [Ml, ← List.length_pos, hpf.limbs_len, limbCount])).trans ?_
      simp only [Ml, List.length_map, hpf.limbs_len, hKlLen, hqLen]
      omega
    rw [← recompose_eq_sumRange hlen, recompose, evalAt_polyMul,
      ← recompose, ← recompose, hKlRec]
    rw [show recompose Ml = c.m from hpf.limbs_rec]
  have hZero : weightedPrefix Res c.positions = 0 := by
    change sumRange c.positions (fun i => Res i * 2 ^ (32 * i)) = 0
    dsimp [Res]
    rw [sumRange_sub_mul, hRsum, hQsum,
      unfolded_eq hb hsf hfold (by omega), evalAt_exprInt]
    have he : R + (c.m : ℤ) * K = E := Int.emod_add_ediv E c.m
    change E - R - K * c.m = 0
    linear_combination -he
  apply checkPolynomial_complete b c hc hpb hl (limbLists es) rl ql K Res
  · exact hrlBound
  · simpa [hfold] using hqlBound
  · intro hf; simp [hfold] at hf
  · intro hf; simp [hfold] at hf
  · exact hResNative
  · exact hResBound
  · exact hZero
  · exact hcapacity
  · cases hw : c.withResult <;> simpa [rl, R, E, hw] using hk

/-- Eval returns the canonical whole-expression remainder. -/
theorem wholeEval_complete (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (hfold : c.fold = false) (hresult : c.withResult = true) (hpb : c.pieceBits = 11)
    (hwidths : c.resultWidths = limbWidths8) (hmWidth : c.m < 2 ^ 256)
    (full top : ℕ)
    (hqw : c.quotientWidths = wholeQuotientWidths full top)
    (hqb : c.quotientBits = 32 * full + top)
    (hqLower : 0 ≤ wholeExpressionLower c / (c.m : ℤ) + c.offset)
    (hqUpper : wholeExpressionUpper c / (c.m : ℤ) + c.offset < 2 ^ c.quotientBits)
    (hcapacity : CarryCapacity (c.residualBound b) c.positions c.carryPositions c.groups 0 none)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    (k : Option (List F) → Prop)
    (hk : k (some ((natLimbs8 ((c.exprValue (values es) % (c.m : ℤ)).toNat)).map
      (Nat.cast : ℕ → F)))) :
    CheckPolynomial.circuit b c (limbLists es) (LookupCheck RangeCheck 11) k := by
  apply wholeCheck_complete b c hbs hc hfold hpb hwidths hmWidth
    full top hqw hqb hqLower hqUpper hcapacity hl es hb
  · intro hf; rw [hresult] at hf; contradiction
  · simpa [hresult] using hk

/-- AssertZero uses the same constructed quotient and an empty remainder.
Its premise is the asserted modular identity, rather than circuit success. -/
theorem wholeAssert_complete (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (hfold : c.fold = false) (hresult : c.withResult = false) (hpb : c.pieceBits = 11)
    (hwidths : c.resultWidths = limbWidths8) (hmWidth : c.m < 2 ^ 256)
    (full top : ℕ)
    (hqw : c.quotientWidths = wholeQuotientWidths full top)
    (hqb : c.quotientBits = 32 * full + top)
    (hqLower : 0 ≤ wholeExpressionLower c / (c.m : ℤ) + c.offset)
    (hqUpper : wholeExpressionUpper c / (c.m : ℤ) + c.offset < 2 ^ c.quotientBits)
    (hcapacity : CarryCapacity (c.residualBound b) c.positions c.carryPositions c.groups 0 none)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    (hzero : c.exprValue (values es) % (c.m : ℤ) = 0)
    (k : Option (List F) → Prop) (hk : k none) :
    CheckPolynomial.circuit b c (limbLists es) (LookupCheck RangeCheck 11) k := by
  apply wholeCheck_complete b c hbs hc hfold hpb hwidths hmWidth
    full top hqw hqb hqLower hqUpper hcapacity hl es hb
  · intro hf; exact hzero
  · simpa [hresult] using hk

end ZolanaVE.Field
