import VerifiableEncryption.Field.CompletenessCheck

/-!
Canonical remainder and quotient construction for folded evaluation checks.
Only static numerical quotient/carry capacity is conditional. All input-dependent
remainder, quotient, residual and hint pieces are constructed from bounded
integer elements, before the generic circuit constructor is applied.
-/

namespace ZolanaVE.Field

open scoped BigOperators

def natLimbs8 (v : ℕ) : List ℕ :=
  [v % 2 ^ 32, v / 2 ^ 32 % 2 ^ 32, v / 2 ^ 64 % 2 ^ 32, v / 2 ^ 96 % 2 ^ 32,
    v / 2 ^ 128 % 2 ^ 32, v / 2 ^ 160 % 2 ^ 32, v / 2 ^ 192 % 2 ^ 32, v / 2 ^ 224 % 2 ^ 32]

def limbWidths8 : List ℕ := [32, 32, 32, 32, 32, 32, 32, 32]

def natLimbVector8 (v : ℕ) : List.Vector F 8 :=
  vec![((v % 2 ^ 32 : ℕ) : F), ((v / 2 ^ 32 % 2 ^ 32 : ℕ) : F),
    ((v / 2 ^ 64 % 2 ^ 32 : ℕ) : F), ((v / 2 ^ 96 % 2 ^ 32 : ℕ) : F),
    ((v / 2 ^ 128 % 2 ^ 32 : ℕ) : F), ((v / 2 ^ 160 % 2 ^ 32 : ℕ) : F),
    ((v / 2 ^ 192 % 2 ^ 32 : ℕ) : F), ((v / 2 ^ 224 % 2 ^ 32 : ℕ) : F)]

theorem natLimbVector8_list (v : ℕ) :
    (natLimbVector8 v).toList = (natLimbs8 v).map (Nat.cast : ℕ → F) := rfl

theorem natLimbs8_bounds (v : ℕ) :
    List.Forall₂ (fun value width => value < 2 ^ width) (natLimbs8 v) limbWidths8 := by
  refine .cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ (.cons ?_ .nil)))))))
  all_goals exact Nat.mod_lt _ (by norm_num)

theorem natLimbs8_recompose (v : ℕ) (hv : v < 2 ^ 256) :
    recompose ((natLimbs8 v).map (Nat.cast : ℕ → ℤ)) = v := by
  norm_num [natLimbs8, recompose, evalAt, lin, limbBase]
  omega

theorem natBounds_getD : ∀ (values widths : List ℕ)
    (h : List.Forall₂ (fun value width => value < 2 ^ width) values widths) (pos : ℕ),
    values.getD pos 0 < 2 ^ (widths.getD pos 0)
  | [], [], h, pos => by simp
  | [], _ :: _, h, pos => by cases h
  | _ :: _, [], h, pos => by cases h
  | v :: vs, w :: ws, h, 0 => by cases h with | cons hv htail => exact hv
  | v :: vs, w :: ws, h, pos + 1 => by
    cases h with
    | cons hv htail => simpa using natBounds_getD vs ws htail pos

theorem getD_natCast_F (l : List ℕ) (pos : ℕ) :
    (l.map (Nat.cast : ℕ → F)).getD pos 0 = (l.getD pos 0 : F) := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_map]
  cases l[pos]? <;> simp

def foldedMagnitude (b : BasisParams) (c : PlainCheckParams) : ℤ :=
  sumRange limbCount (fun i => c.toPolyShape.foldedBound b i * 2 ^ (32 * i))

def foldedValue (b : BasisParams) (c : PlainCheckParams) (es : List (Σ w, ElemVal w)) : ℤ :=
  sumRange limbCount (fun i => foldedInt b c.toPolyShape es i * 2 ^ (32 * i))

theorem foldedValue_bound (b : BasisParams) (c : PlainCheckParams)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    (hsf : ShapeFacts b c.toPolyShape c.m) (hfold : c.fold = true) :
    |foldedValue b c es| ≤ foldedMagnitude b c := by
  refine (abs_sumRange_le _ _).trans ?_
  apply sumRange_le_sumRange
  intro i hi
  rw [abs_mul, abs_of_pos (by positivity : (0 : ℤ) < 2 ^ (32 * i))]
  apply mul_le_mul_of_nonneg_right ?_ (by positivity)
  simpa only [hfold, if_true] using foldedInt_bound hb hsf i

theorem foldedValue_congr (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true) (hf : c.fold = true)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems) :
    foldedValue b c es ≡ c.exprValue (values es) [ZMOD (c.m : ℤ)] := by
  have hsf := shapeFacts (plainFacts hc).shape
  have he := folded_congr (basisFacts hbs) hb hsf hf
  rw [← (hsf.fold hf).1, evalAt_exprInt] at he
  exact he

/-- Complete a folded Eval from bounded inputs. The two quotient inequalities
and CarryCapacity concern only the certificate, not input/hint success. The
canonical remainder is E mod m, the quotient is E / m, and all native pieces
and carry gates are supplied by checkPolynomial_complete. -/
theorem foldedCheck_complete (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (hfold : c.fold = true) (hpb : c.pieceBits = 11)
    (hwidths : c.resultWidths = limbWidths8) (hmWidth : c.m < 2 ^ 256)
    (hqLower : foldedMagnitude b c + (if c.withResult then (c.m : ℤ) - 1 else 0) ≤
      (c.offset : ℤ) * c.m)
    (hqUpper : foldedMagnitude b c < ((2 : ℤ) ^ c.quotientBits - c.offset) * c.m)
    (hcapacity : CarryCapacity (c.residualBound b) c.positions c.carryPositions c.groups 0 none)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    (hnoResultZero : c.withResult = false → foldedValue b c es % (c.m : ℤ) = 0)
    (k : Option (List F) → Prop)
    (hk : k (if c.withResult then
      some ((natLimbs8 ((foldedValue b c es % (c.m : ℤ)).toNat)).map (Nat.cast : ℕ → F)) else none)) :
    CheckPolynomial.circuit b c (limbLists es) (LookupCheck RangeCheck 11) k := by
  have hpf := plainFacts hc
  have hbf := basisFacts hbs
  have hsf := shapeFacts hpf.shape
  let E := foldedValue b c es
  let R : ℤ := E % (c.m : ℤ)
  let K : ℤ := E / (c.m : ℤ)
  let rl := if c.withResult then natLimbs8 R.toNat else []
  let Ml := c.modulusLimbs.map (Nat.cast : ℕ → ℤ)
  let Kl : List ℤ := [K]
  let Res := fun pos => foldedInt b c.toPolyShape es pos -
    ((rl.getD pos 0 : ℕ) : ℤ) - (polyMul Kl Ml).getD pos 0
  have hm : (0 : ℤ) < c.m := by exact_mod_cast hpf.m_pos
  have hR0 : 0 ≤ R := Int.emod_nonneg _ (by omega)
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
  have hRMax : R ≤ if c.withResult then (c.m : ℤ) - 1 else 0 := by
    cases hw : c.withResult
    · simp [hw, hRZero hw]
    · simp only [hw, if_true]
      omega
  have hE : E = R + (c.m : ℤ) * K := (Int.emod_add_ediv E c.m).symm
  have hEB := foldedValue_bound b c es hb hsf hfold
  change |E| ≤ foldedMagnitude b c at hEB
  have hKrange : 0 ≤ K + c.offset ∧ K + c.offset < 2 ^ c.quotientBits := by
    rw [abs_le] at hEB
    constructor <;> nlinarith
  have hKabs : |K| ≤ c.quotientMagnitude := by
    apply abs_le_shiftedBound
    · omega
    · omega
  have hKlBound : ∀ i, |Kl.getD i 0| ≤ c.quotientLimbBound i := by
    intro i
    simp only [PlainCheckParams.quotientLimbBound, hfold, if_true]
    cases i with
    | zero => exact hKabs
    | succ i => simpa [Kl] using shiftedBound_nonneg c.offset c.quotientBits
  have hKlLen : Kl.length ≤ c.quotientLimbCount := by
    simp [Kl, PlainCheckParams.quotientLimbCount, hfold]
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
    simp only [hfold, if_true] at hA
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
    have hQ := quotientTerm_bound c hpf.limbs_len hKlLen hKlBound pos
    unfold PlainCheckParams.residualBound
    simp only [hfold, if_true]
    dsimp [Res]
    calc
      |foldedInt b c.toPolyShape es pos - ((rl.getD pos 0 : ℕ) : ℤ) -
          (polyMul Kl Ml).getD pos 0| ≤
          |foldedInt b c.toPolyShape es pos| + |((rl.getD pos 0 : ℕ) : ℤ)| +
          |(polyMul Kl Ml).getD pos 0| := (abs_sub _ _).trans (add_le_add_right (abs_sub _ _) _)
      _ ≤ _ := add_le_add (add_le_add hA hRi) hQ
  have hRnative : sumRange limbCount (fun i =>
      (rl.map (Nat.cast : ℕ → F)).getD i 0 * pow32 i) = (R : F) := by
    have hs := recompose_eq_sumRange (row := rl.map (Nat.cast : ℕ → ℤ))
      (n := limbCount) (by simpa using hrlLen)
    rw [hRrec] at hs
    have hsF := congrArg (fun v : ℤ => (v : F)) hs
    simp only [intCast_sumRange, Int.cast_mul, getD_map_natCast, Int.cast_natCast,
      Int.cast_pow, Int.cast_ofNat] at hsF
    simpa only [getD_natCast_F, pow32] using hsF.symm
  have hEnative : sumRange limbCount (fun i =>
      exprVal b c.toPolyShape (limbLists es) i * pow32 i) = (E : F) := by
    dsimp [E, foldedValue]
    rw [intCast_sumRange]
    apply sumRange_congr
    intro i hi
    rw [exprVal_eq hbf hb hsf]
    push_cast
    rfl
  have hmInv : (c.m : F) * (c.mInv : F) = 1 := by
    have hi : ((c.m * c.mInv : ℕ) : F) = 1 := by
      rw [← ZMod.natCast_mod, hpf.m_inv, Nat.cast_one]
    simpa only [Nat.cast_mul] using hi
  have hFoldNative : CheckPolynomial.foldQuotient b c (limbLists es)
      (rl.map (Nat.cast : ℕ → F)) = (K : F) := by
    apply foldQuotient_of_integer b c _ _ K hmInv
    rw [hEnative, hRnative]
    have heF := congrArg (fun v : ℤ => (v : F)) hE
    push_cast at heF
    linear_combination heF
  have hResNative : ∀ pos, (Res pos : F) = CheckPolynomial.residual b c (limbLists es)
      (rl.map (Nat.cast : ℕ → F)) [] (K : F) pos := by
    intro pos
    have hM := modulusLimbs_getD c hpf.limbs_len pos
    dsimp [Res, Kl, Ml]
    rw [getD_polyMul_single]
    simp only [Int.cast_sub, Int.cast_mul, Int.cast_natCast, getD_natCast_F,
      CheckPolynomial.residual, hfold, if_true, ← exprVal_eq hbf hb hsf]
    rw [hM]
    split_ifs <;> simp
  have hZero : weightedPrefix Res c.positions = 0 := by
    rw [(hpf.folded hfold).1]
    have hRsum := recompose_eq_sumRange (row := rl.map (Nat.cast : ℕ → ℤ))
      (n := limbCount) (by simpa using hrlLen)
    rw [hRrec] at hRsum
    simp only [getD_map_natCast] at hRsum
    have hMsum := recompose_eq_sumRange (row := Ml) (n := limbCount)
      (by simp [Ml, hpf.limbs_len])
    rw [show recompose Ml = c.m from hpf.limbs_rec] at hMsum
    have hQsum : sumRange limbCount (fun i => (polyMul Kl Ml).getD i 0 * 2 ^ (32 * i)) = K * c.m := by
      dsimp [Kl]
      simp only [getD_polyMul_single]
      rw [hMsum, sumRange_eq, sumRange_eq, Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro i hi
      ring
    change sumRange limbCount (fun i => Res i * 2 ^ (32 * i)) = 0
    dsimp [Res]
    rw [sumRange_sub_mul, ← hRsum, hQsum]
    change E - R - K * c.m = 0
    linear_combination hE
  apply checkPolynomial_complete b c hc hpb hl (limbLists es) rl [] K Res
  · exact hrlBound
  · simp [hfold]
  · intro hf; exact hFoldNative
  · intro hf; exact hKrange
  · exact hResNative
  · exact hResBound
  · exact hZero
  · exact hcapacity
  · cases hw : c.withResult <;> simpa [rl, R, E, hw] using hk

/-- Folded Eval specialization, retaining the public constructor interface. -/
theorem foldedEval_complete (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (hfold : c.fold = true) (hresult : c.withResult = true) (hpb : c.pieceBits = 11)
    (hwidths : c.resultWidths = limbWidths8) (hmWidth : c.m < 2 ^ 256)
    (hqLower : foldedMagnitude b c + (c.m : ℤ) - 1 ≤ (c.offset : ℤ) * c.m)
    (hqUpper : foldedMagnitude b c < ((2 : ℤ) ^ c.quotientBits - c.offset) * c.m)
    (hcapacity : CarryCapacity (c.residualBound b) c.positions c.carryPositions c.groups 0 none)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    (k : Option (List F) → Prop)
    (hk : k (some ((natLimbs8 ((foldedValue b c es % (c.m : ℤ)).toNat)).map (Nat.cast : ℕ → F)))) :
    CheckPolynomial.circuit b c (limbLists es) (LookupCheck RangeCheck 11) k := by
  apply foldedCheck_complete b c hbs hc hfold hpb hwidths hmWidth
    (by simpa [hresult, add_sub_assoc] using hqLower) hqUpper hcapacity hl es hb
  · intro hf
    rw [hresult] at hf
    contradiction
  · simpa [hresult] using hk

/-- Folded AssertZero specialization. The only input-dependent premise is
the mathematical expression congruence; no hint or constraint succeeds by assumption. -/
theorem foldedAssert_complete (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (hfold : c.fold = true) (hresult : c.withResult = false) (hpb : c.pieceBits = 11)
    (hwidths : c.resultWidths = limbWidths8) (hmWidth : c.m < 2 ^ 256)
    (hqLower : foldedMagnitude b c ≤ (c.offset : ℤ) * c.m)
    (hqUpper : foldedMagnitude b c < ((2 : ℤ) ^ c.quotientBits - c.offset) * c.m)
    (hcapacity : CarryCapacity (c.residualBound b) c.positions c.carryPositions c.groups 0 none)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    (hzero : foldedValue b c es % (c.m : ℤ) = 0)
    (k : Option (List F) → Prop) (hk : k none) :
    CheckPolynomial.circuit b c (limbLists es) (LookupCheck RangeCheck 11) k := by
  apply foldedCheck_complete b c hbs hc hfold hpb hwidths hmWidth
    (by simpa [hresult] using hqLower) hqUpper hcapacity hl es hb
  · intro hf; exact hzero
  · simpa [hresult] using hk

theorem foldedAssert_of_expr (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (hfold : c.fold = true) (hresult : c.withResult = false) (hpb : c.pieceBits = 11)
    (hwidths : c.resultWidths = limbWidths8) (hmWidth : c.m < 2 ^ 256)
    (hqLower : foldedMagnitude b c ≤ (c.offset : ℤ) * c.m)
    (hqUpper : foldedMagnitude b c < ((2 : ℤ) ^ c.quotientBits - c.offset) * c.m)
    (hcapacity : CarryCapacity (c.residualBound b) c.positions c.carryPositions c.groups 0 none)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    (hzero : c.exprValue (values es) ≡ 0 [ZMOD (c.m : ℤ)])
    (k : Option (List F) → Prop) (hk : k none) :
    CheckPolynomial.circuit b c (limbLists es) (LookupCheck RangeCheck 11) k := by
  apply foldedAssert_complete b c hbs hc hfold hresult hpb hwidths hmWidth
    hqLower hqUpper hcapacity hl es hb _ k hk
  have he := (foldedValue_congr b c hbs hc hfold es hb).trans hzero
  simpa [Int.ModEq] using he

end ZolanaVE.Field
