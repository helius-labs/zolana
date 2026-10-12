import VerifiableEncryption.Field.CompletenessRange

/-!
Construct the generic production arithmetic check from integer polynomial
witnesses. Remainder and quotient limbs are supplied as mathematical integers,
not satisfying constraints; their pieces and all carry values are constructed.
Native-polynomial identities, integer-zero residual, and static capacity are
explicit contracts to discharge from each concrete operation's arithmetic.
-/

namespace ZolanaVE.Field

open scoped BigOperators

theorem foldQuotient_of_integer (b : BasisParams) (c : PlainCheckParams)
    (xs : List (List F)) (r : List F) (K : ℤ)
    (hinv : (c.m : F) * (c.mInv : F) = 1)
    (heq : sumRange limbCount (fun j => exprVal b c.toPolyShape xs j * pow32 j) -
      sumRange limbCount (fun j => r.getD j 0 * pow32 j) = (K : F) * (c.m : F)) :
    CheckPolynomial.foldQuotient b c xs r = (K : F) := by
  unfold CheckPolynomial.foldQuotient
  rw [heq, mul_assoc, hinv, mul_one]

/-- Construct a full generic CheckPolynomial witness, including range pieces,
shifted folded quotient, native whole equation, grouped carries and top check.
No CheckPolynomial or successful hint premise appears in the hypotheses. -/
theorem checkPolynomial_complete (b : BasisParams) (c : PlainCheckParams)
    (hc : c.sound b = true) (hpb : c.pieceBits = 11)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (xs : List (List F)) (rl ql : List ℕ) (K : ℤ) (Res : ℕ → ℤ)
    (hr : List.Forall₂ (fun value width => value < 2 ^ width) rl
      (if c.withResult then c.resultWidths else []))
    (hq : List.Forall₂ (fun value width => value < 2 ^ width) ql
      (if c.fold then [] else c.quotientWidths))
    (hfold : c.fold = true → CheckPolynomial.foldQuotient b c xs (rl.map (Nat.cast : ℕ → F)) = (K : F))
    (hK : c.fold = true → 0 ≤ K + c.offset ∧ K + c.offset < 2 ^ c.quotientBits)
    (hres : ∀ pos, (Res pos : F) = CheckPolynomial.residual b c xs
      (rl.map (Nat.cast : ℕ → F)) (ql.map (Nat.cast : ℕ → F)) (K : F) pos)
    (hbound : ∀ pos, |Res pos| ≤ c.residualBound b pos)
    (hzero : weightedPrefix Res c.positions = 0)
    (hcapacity : CarryCapacity (c.residualBound b) c.positions c.carryPositions c.groups 0 none)
    (k : Option (List F) → Prop)
    (hk : k (if c.withResult then some (rl.map (Nat.cast : ℕ → F)) else none)) :
    CheckPolynomial.circuit b c xs (LookupCheck RangeCheck 11) k := by
  have hpf := plainFacts hc
  let rw := if c.withResult then c.resultWidths else []
  let qw := if c.fold then [] else c.quotientWidths
  let rp := widthPieces rw rl
  let qp := widthPieces qw ql
  obtain ⟨hrp, hrMap⟩ := widthPieces_complete hl rw rl hr
  obtain ⟨hqp, hqMap⟩ := widthPieces_complete hl qw ql hq
  have hrNil : c.withResult = false → rl = [] := by
    intro hw
    have he := hr.length_eq
    simp only [hw, Bool.false_eq_true, if_false, List.length_nil] at he
    exact List.length_eq_zero.mp he
  have hqNil : c.fold = true → ql = [] := by
    intro hf
    have he := hq.length_eq
    simp only [hf, if_true, List.length_nil] at he
    exact List.length_eq_zero.mp he
  have hRP : (if c.withResult then PiecesOk (LookupCheck RangeCheck 11) 11 c.resultWidths rp else rp = []) := by
    cases hw : c.withResult
    · simp [rp, rw, hw, widthPieces]
    · simpa [rp, rw, hw] using hrp
  have hQP : (if c.fold then qp = [] else PiecesOk (LookupCheck RangeCheck 11) 11 c.quotientWidths qp) := by
    cases hf : c.fold
    · simpa [qp, qw, hf] using hqp
    · simp [qp, qw, hf, widthPieces]
  have hR : (if c.withResult then limbsOfPieces 11 c.resultWidths rp else []) =
      rl.map (Nat.cast : ℕ → F) := by
    cases hw : c.withResult
    · simp [hw, hrNil hw]
    · simpa [rp, rw, hw] using hrMap
  have hQ : (if c.fold then [] else limbsOfPieces 11 c.quotientWidths qp) =
      ql.map (Nat.cast : ℕ → F) := by
    cases hf : c.fold
    · simpa [qp, qw, hf] using hqMap
    · simp [hf, hqNil hf]
  let nativeQuotient := CheckPolynomial.foldQuotient b c xs (rl.map (Nat.cast : ℕ → F))
  let nativeResidual := CheckPolynomial.residual b c xs
    (rl.map (Nat.cast : ℕ → F)) (ql.map (Nat.cast : ℕ → F)) nativeQuotient
  have hResNative : ∀ pos, (Res pos : F) = nativeResidual pos := by
    intro pos
    by_cases hf : c.fold = true
    · simpa [nativeResidual, nativeQuotient, hfold hf] using hres pos
    · have hf' : c.fold = false := by simpa using hf
      simpa [nativeResidual, CheckPolynomial.residual, hf'] using hres pos
  unfold CheckPolynomial.circuit
  rw [hpb]
  refine ⟨rp, qp, hRP, hQP, ?_⟩
  dsimp only
  rw [hR, hQ]
  refine ⟨?_, ?_, ?_⟩
  · intro hf
    rw [hfold hf]
    obtain ⟨hK0, hKlt⟩ := hK hf
    have hbits := (hpf.folded hf).2
    have hnat : (K + c.offset).toNat < 2 ^ c.quotientBits := by
      have hi : (((K + c.offset).toNat : ℕ) : ℤ) < (2 : ℤ) ^ c.quotientBits := by
        rw [Int.toNat_of_nonneg hK0]
        exact hKlt
      exact_mod_cast hi
    have hm := lookupCheck_complete hl c.quotientBits (K + c.offset).toNat hbits hnat
    convert hm using 1
    symm
    rw [← Int.cast_natCast, Int.toNat_of_nonneg hK0]
    push_cast
    rfl
  · intro hgeneral
    have hz := congrArg (fun z : ℤ => (z : F)) hzero
    simpa only [weightedPrefix, intCast_sumRange, Int.cast_mul, hResNative,
      carryRadix, Int.cast_pow, Int.cast_ofNat, pow32, Int.cast_zero] using hz
  · apply carryChain_complete (lookupCheck_complete hl) hResNative hbound hzero
      hpf.cp_lt.le c.groups 0 none 0 _ hcapacity
      (by simp [PlainCheckParams.carryIn]) (by simp [weightedPrefix, sumRange])
    refine ⟨?_, hk⟩
    intro htop
    obtain ⟨prev, hwalk, htopFacts, hmag⟩ := hpf.groups
    have hpositions := (htopFacts htop).1
    let C := weightedPrefix Res c.carryPositions / carryRadix c.carryPositions
    have hC : C * carryRadix c.carryPositions = weightedPrefix Res c.carryPositions :=
      Int.ediv_mul_cancel (weightedPrefix_dvd hzero hpf.cp_lt.le)
    have hsplit : weightedPrefix Res (c.carryPositions + 1) =
        weightedPrefix Res c.carryPositions + Res c.carryPositions * carryRadix c.carryPositions := by
      simp [weightedPrefix, sumRange, List.range_succ]
    have ht := hzero
    rw [← hpositions, hsplit, ← hC] at ht
    have htopInt : Res c.carryPositions + C = 0 := by
      apply (mul_eq_zero.mp ?_).resolve_right (ne_of_gt (carryRadix_pos c.carryPositions))
      linear_combination ht
    have htF := congrArg (fun z : ℤ => (z : F)) htopInt
    simpa only [Int.cast_add, hResNative, Int.cast_zero, C] using htF

end ZolanaVE.Field
