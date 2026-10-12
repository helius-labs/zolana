import VerifiableEncryption.Field.Layout

/-! A native Boolean as the same bounded one-limb emulated-field element.
Shared by complete addition and the middle-step native-zero fallback. -/

namespace ZolanaVE.P256

open ZolanaVE.Field

def bitElem (b : Bool) : ElemVal 1 where
  limbs := (if b then 1 else 0) ::ᵥ List.Vector.nil
  ints := (if b then 1 else 0) ::ᵥ List.Vector.nil
  lo := 0 ::ᵥ List.Vector.nil
  hi := 1 ::ᵥ List.Vector.nil
  vlo := 0
  vhi := 1
  h_cast := by intro i; fin_cases i; cases b <;> simp
  h_lo := by intro i; fin_cases i; cases b <;> simp
  h_hi := by intro i; fin_cases i; cases b <;> simp
  h_vlo := by cases b <;> simp [recompose, evalAt_cons]
  h_vhi := by cases b <;> simp [recompose, evalAt_cons]

theorem bitElem_value (b : Bool) : (bitElem b).value = if b then 1 else 0 := by
  cases b <;> simp [bitElem, ElemVal.value, recompose, evalAt_cons]

/-- Extracted IsZero semantics produce the actual integer bit used by both
native and emulated fields. A false flag certifies the native input nonzero. -/
theorem isZero_bit {input output : F} (h : GatesDef.is_zero input output) :
    ∃ b : Bool, output = (if b then 1 else 0) ∧ (b = false → input ≠ 0) := by
  rcases h with ⟨hn, ho⟩ | ⟨hz, ho⟩
  · exact ⟨false, ho, fun _ => hn⟩
  · refine ⟨true, ho, ?_⟩
    intro he
    cases he

end ZolanaVE.P256
