import VerifiableEncryption.Field.CompletenessWholeEval
import VerifiableEncryption.Field.Certificate

/-! Concrete nonfolded scalar certificate capacities and generic-model
witnesses. Input bounds retain the full 256-bit encoding interval. Extracted
primitive reverse bridges and ladder composition are separate obligations. -/

namespace ZolanaVE.Field

open ZolanaVE.EmcurveChecks

theorem scalarEval_quotient_lower :
    0 ≤ wholeExpressionLower cert_h57d6a69c / (cert_h57d6a69c.m : ℤ) + cert_h57d6a69c.offset := by
  decide +kernel

theorem scalarEval_quotient_upper :
    wholeExpressionUpper cert_h57d6a69c / (cert_h57d6a69c.m : ℤ) + cert_h57d6a69c.offset <
      2 ^ cert_h57d6a69c.quotientBits := by
  decide +kernel

theorem halfScalarEval_quotient_lower :
    0 ≤ wholeExpressionLower cert_h93312e5c / (cert_h93312e5c.m : ℤ) + cert_h93312e5c.offset := by
  decide +kernel

theorem halfScalarEval_quotient_upper :
    wholeExpressionUpper cert_h93312e5c / (cert_h93312e5c.m : ℤ) + cert_h93312e5c.offset <
      2 ^ cert_h93312e5c.quotientBits := by
  decide +kernel

theorem scalarDecomp_quotient_lower :
    0 ≤ wholeExpressionLower cert_hb0ad1306 / (cert_hb0ad1306.m : ℤ) + cert_hb0ad1306.offset := by
  decide +kernel

theorem scalarDecomp_quotient_upper :
    wholeExpressionUpper cert_hb0ad1306 / (cert_hb0ad1306.m : ℤ) + cert_hb0ad1306.offset <
      2 ^ cert_hb0ad1306.quotientBits := by
  decide +kernel

theorem scalarEval_carry_capacity :
    CarryCapacity (cert_h57d6a69c.residualBound basis) cert_h57d6a69c.positions
      cert_h57d6a69c.carryPositions cert_h57d6a69c.groups 0 none := by
  change CarryCapacity (cert_h57d6a69c.residualBound basis) 8 1
    [⟨0, 1, 2, 20520227687253066844553443099509678173442728246946192144187700041656053926509⟩] 0 none
  apply CarryCapacity.cons
  · rfl
  · norm_num
  · norm_num
  · norm_num
  · decide +kernel
  · decide +kernel
  · exact CarryCapacity.nil _

theorem halfScalarEval_carry_capacity :
    CarryCapacity (cert_h93312e5c.residualBound basis) cert_h93312e5c.positions
      cert_h93312e5c.carryPositions cert_h93312e5c.groups 0 none := by
  change CarryCapacity (cert_h93312e5c.residualBound basis) 15 9
    [⟨0, 6, 36, 19460348035796462271896288287919407799161393094049025387841668571217901960782⟩,
      ⟨6, 9, 36, 6533163946079935388699578594191215037746566342452551272410847553401545914805⟩] 0 none
  apply CarryCapacity.cons
  · rfl
  · norm_num
  · norm_num
  · norm_num
  · decide +kernel
  · decide +kernel
  · apply CarryCapacity.cons
    · rfl
    · norm_num
    · norm_num
    · norm_num
    · decide +kernel
    · decide +kernel
    · exact CarryCapacity.nil _

theorem scalarDecomp_carry_capacity :
    CarryCapacity (cert_hb0ad1306.residualBound basis) cert_hb0ad1306.positions
      cert_hb0ad1306.carryPositions cert_hb0ad1306.groups 0 none := by
  change CarryCapacity (cert_hb0ad1306.residualBound basis) 12 5
    [⟨0, 5, 35, 13083695485769087878095579780392118994716161154349678186313392586051322996696⟩] 0 none
  apply CarryCapacity.cons
  · rfl
  · norm_num
  · norm_num
  · norm_num
  · decide +kernel
  · decide +kernel
  · exact CarryCapacity.nil _

theorem scalarEval_model_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_h57d6a69c.elems)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (k : Option (List F) → Prop)
    (hk : k (some ((natLimbs8 ((cert_h57d6a69c.exprValue (values es) %
      (cert_h57d6a69c.m : ℤ)).toNat)).map (Nat.cast : ℕ → F)))) :
    CheckPolynomial.circuit basis cert_h57d6a69c (limbLists es) (LookupCheck RangeCheck 11) k := by
  exact wholeEval_complete basis cert_h57d6a69c basis_sound cert_h57d6a69c_sound
    rfl rfl rfl rfl (by norm_num [cert_h57d6a69c]) 0 2 rfl rfl
    scalarEval_quotient_lower scalarEval_quotient_upper scalarEval_carry_capacity hl es hb k hk

theorem halfScalarEval_model_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_h93312e5c.elems)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (k : Option (List F) → Prop)
    (hk : k (some ((natLimbs8 ((cert_h93312e5c.exprValue (values es) %
      (cert_h93312e5c.m : ℤ)).toNat)).map (Nat.cast : ℕ → F)))) :
    CheckPolynomial.circuit basis cert_h93312e5c (limbLists es) (LookupCheck RangeCheck 11) k := by
  exact wholeEval_complete basis cert_h93312e5c basis_sound cert_h93312e5c_sound
    rfl rfl rfl rfl (by norm_num [cert_h93312e5c]) 7 32 rfl rfl
    halfScalarEval_quotient_lower halfScalarEval_quotient_upper halfScalarEval_carry_capacity hl es hb k hk

theorem scalarDecomp_model_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_hb0ad1306.elems)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (hzero : cert_hb0ad1306.exprValue (values es) % (cert_hb0ad1306.m : ℤ) = 0)
    (k : Option (List F) → Prop) (hk : k none) :
    CheckPolynomial.circuit basis cert_hb0ad1306 (limbLists es) (LookupCheck RangeCheck 11) k := by
  exact wholeAssert_complete basis cert_hb0ad1306 basis_sound cert_hb0ad1306_sound
    rfl rfl rfl rfl (by norm_num [cert_hb0ad1306]) 4 3 rfl rfl
    scalarDecomp_quotient_lower scalarDecomp_quotient_upper scalarDecomp_carry_capacity hl es hb hzero k hk

theorem scalarDecomp_model_of_congr (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_hb0ad1306.elems)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (hzero : cert_hb0ad1306.exprValue (values es) ≡ 0 [ZMOD (cert_hb0ad1306.m : ℤ)])
    (k : Option (List F) → Prop) (hk : k none) :
    CheckPolynomial.circuit basis cert_hb0ad1306 (limbLists es) (LookupCheck RangeCheck 11) k := by
  apply scalarDecomp_model_complete es hb hl _ k hk
  simpa [Int.ModEq] using hzero

end ZolanaVE.Field
