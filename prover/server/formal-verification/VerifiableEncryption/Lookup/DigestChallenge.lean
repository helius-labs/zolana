import VerifiableEncryption.Lookup.Challenge
import VerifiableEncryption.ParameterCertificates.BN254
import VerifiableEncryption.Circuit.Prelude

/-!
Bias of an ideal uniform 256-bit digest reduced by Fr.SetBytes. Digest words
are uniform on `Fin (2^256)`, not on the native field. Every reduction fiber
has at most six words, giving point-mass cap `6/2^256`; callback powers get
cap `6r/2^256`. This does not assert that a configured public hash or an
adaptively selected/grinded digest is uniformly random.
-/

namespace ZolanaVE.Lookup

open scoped BigOperators

variable [Fact (Nat.Prime Order)]

abbrev DigestWord := Fin (2 ^ 256)

def digestWordToField (word : DigestWord) : F := (word.val : F)

theorem digest_word_bound : 2 ^ 256 < 6 * Order := by
  unfold Order
  norm_num

theorem digestWord_quotient_bound (word : DigestWord) : word.val / Order < 6 := by
  have horder : 0 < Order := by unfold Order; norm_num
  apply (Nat.div_lt_iff_lt_mul horder).mpr
  exact lt_trans word.isLt digest_word_bound

def digestFiber (value : F) : Finset DigestWord :=
  Finset.univ.filter (fun word => digestWordToField word = value)

def digestFiberClass (value : F) (word : {word : DigestWord // word ∈ digestFiber value}) : Fin 6 :=
  ⟨word.val.val / Order, digestWord_quotient_bound word.val⟩

theorem digestFiberClass_injective (value : F) : Function.Injective (digestFiberClass value) := by
  intro a b he
  have hquotient : a.val.val / Order = b.val.val / Order := congrArg Fin.val he
  have ha := congrArg ZMod.val (Finset.mem_filter.mp a.property).2
  have hb := congrArg ZMod.val (Finset.mem_filter.mp b.property).2
  simp only [digestWordToField, ZMod.val_natCast] at ha hb
  have hword : a.val.val = b.val.val := by
    calc
      a.val.val = a.val.val % Order + Order * (a.val.val / Order) := (Nat.mod_add_div _ _).symm
      _ = b.val.val % Order + Order * (b.val.val / Order) := by rw [ha, hb, hquotient]
      _ = b.val.val := Nat.mod_add_div _ _
  exact Subtype.ext (Fin.ext hword)

theorem digestFiber_card_le (value : F) : (digestFiber value).card ≤ 6 := by
  have hc := Fintype.card_le_of_injective (digestFiberClass value) (digestFiberClass_injective value)
  simpa only [Fintype.card_coe, Fintype.card_fin] using hc

noncomputable def idealDigestWords : Distribution DigestWord where
  mass := fun _ => 1 / (2 ^ 256 : ℚ)
  nonneg := fun _ => by positivity
  normalized := by
    simp only [Finset.sum_const, Finset.card_univ, Fintype.card_fin, nsmul_eq_mul]
    norm_num

noncomputable def idealDigestReduction : Distribution F :=
  idealDigestWords.pushforward digestWordToField

theorem idealDigestReduction_mass_eq (value : F) :
    idealDigestReduction.mass value = ((digestFiber value).card : ℚ) / (2 ^ 256 : ℚ) := by
  simp [idealDigestReduction, Distribution.pushforward, idealDigestWords, digestFiber,
    div_eq_mul_inv]

theorem idealDigestReduction_point_cap (value : F) :
    idealDigestReduction.mass value ≤ 6 / (2 ^ 256 : ℚ) := by
  rw [idealDigestReduction_mass_eq]
  apply div_le_div_of_nonneg_right
  · exact_mod_cast digestFiber_card_le value
  · positivity

theorem idealDigestReduction_callback_point_cap (r : ℕ) (hr : 0 < r) (value : F) :
    (idealDigestReduction.pushforward (fun x => x ^ r)).mass value ≤
      ((6 * r : ℕ) : ℚ) / (2 ^ 256 : ℚ) := by
  have hb := power_pushforward_mass_le idealDigestReduction (6 / (2 ^ 256 : ℚ))
    (by positivity) idealDigestReduction_point_cap r hr value
  convert hb using 1 <;> push_cast <;> ring

end ZolanaVE.Lookup
