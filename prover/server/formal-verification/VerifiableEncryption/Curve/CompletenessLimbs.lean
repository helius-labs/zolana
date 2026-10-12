import VerifiableEncryption.Curve.Completeness
import VerifiableEncryption.Curve.CombWindows
import VerifiableEncryption.Field.CompletenessCheck

/-! Canonical and balanced limb witnesses for mathematical P-256 slopes.
The balanced encoding follows the production BalanceHint's offset/reduction
algorithm, but witness existence remains separate from Go hint correctness. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

def balanceOffset : ℕ :=
  2 ^ 31 * (1 + 2 ^ 32 + 2 ^ 64 + 2 ^ 96 + 2 ^ 128 + 2 ^ 160 + 2 ^ 192 + 2 ^ 224)

theorem balanceOffset_eq : (balanceOffset : ℤ) = 2 ^ 31 * balRec := by
  norm_num [balanceOffset, balRec, rec8]

def balancedUnsigned (l : Fp) : ℕ := (l.val + balanceOffset) % p

def signedSlopeInts (l : Fp) (i : Fin 8) : ℤ := xInts (balancedUnsigned l) i - 2 ^ 31

theorem signedSlope_bounds (l : Fp) (i : Fin 8) :
    -2 ^ 31 ≤ signedSlopeInts l i ∧ signedSlopeInts l i ≤ 2 ^ 31 - 1 := by
  have hb : 0 ≤ xInts (balancedUnsigned l) i ∧ xInts (balancedUnsigned l) i < 2 ^ 32 := by
    unfold xInts
    constructor
    · positivity
    · exact_mod_cast Nat.mod_lt (balancedUnsigned l / 2 ^ (32 * i.val)) (by norm_num : 0 < 2 ^ 32)
  unfold signedSlopeInts
  norm_num at hb ⊢
  omega

theorem signedSlope_fits (l : Fp) : Fits (signedSlopeInts l) balC := by
  apply fits_uni
  · exact signedSlope_bounds l
  · exact rec8_bal_bounds (signedSlope_bounds l)

def slopeElem (l : Fp) : ElemVal 8 := mkElem (signedSlopeInts l) balC (signedSlope_fits l)

theorem slopeElem_value (l : Fp) :
    (slopeElem l).value = (balancedUnsigned l : ℤ) - balanceOffset := by
  rw [slopeElem, mkElem_value]
  have hu : balancedUnsigned l < 2 ^ 256 :=
    lt_trans (Nat.mod_lt _ (by norm_num [p])) p_lt_two_pow
  have hshift : rec8 (signedSlopeInts l) = rec8 (xInts (balancedUnsigned l)) - 2 ^ 31 * balRec := by
    unfold signedSlopeInts balRec rec8
    ring
  rw [hshift, rec8_xInts hu, balanceOffset_eq]

theorem slopeElem_cast (l : Fp) : ((slopeElem l).value : Fp) = l := by
  rw [slopeElem_value]
  push_cast
  unfold balancedUnsigned
  rw [ZMod.natCast_mod, Nat.cast_add, ZMod.natCast_zmod_val]
  ring

def unsignedSlopeLimb (l : Fp) (i : ℕ) : ℕ := balancedUnsigned l / 2 ^ (32 * i) % 2 ^ 32

def slopePiece (l : Fp) (j : ℕ) : ℕ :=
  let v := unsignedSlopeLimb l (j / 3)
  if j % 3 = 0 then v % 2048 else if j % 3 = 1 then v / 2048 % 2048 else v / 4194304

def slopePieces (l : Fp) : List.Vector F 24 := List.Vector.ofFn (fun j => (slopePiece l j : F))

theorem slopePieces_get (l : Fp) (i : Fin 8) (j : Fin 3) :
    (slopePieces l).get ⟨3 * i.val + j.val, by omega⟩ =
      ((if j.val = 0 then unsignedSlopeLimb l i % 2048 else
        if j.val = 1 then unsignedSlopeLimb l i / 2048 % 2048 else
          unsignedSlopeLimb l i / 4194304 : ℕ) : F) := by
  have hdiv : (3 * i.val + j.val) / 3 = i.val := by omega
  have hmod : (3 * i.val + j.val) % 3 = j.val := by omega
  simp [slopePieces, slopePiece, hdiv, hmod]

theorem unsignedSlopeLimb_lt (l : Fp) (i : ℕ) : unsignedSlopeLimb l i < 2 ^ 32 :=
  Nat.mod_lt _ (by norm_num)

/-- All 24 actual HintBalanced range pieces are constructed. -/
theorem slopePieces_ranges (hr : RangeComplete) (l : Fp) (i : Fin 8) :
    RangeCheck 11 ((slopePieces l).get ⟨3 * i.val, by omega⟩) ∧
    RangeCheck 11 ((slopePieces l).get ⟨3 * i.val + 1, by omega⟩) ∧
    RangeCheck 10 ((slopePieces l).get ⟨3 * i.val + 2, by omega⟩) := by
  have hb := unsignedSlopeLimb_lt l i
  have h0 := slopePieces_get l i 0
  have h1 := slopePieces_get l i 1
  have h2 := slopePieces_get l i 2
  simp only [Fin.val_zero, Fin.val_one, Fin.val_two, Nat.add_zero, if_true,
    show (1 : ℕ) ≠ 0 by decide, show (2 : ℕ) ≠ 0 by decide,
    show (2 : ℕ) ≠ 1 by decide, if_false] at h0 h1 h2
  rw [h0, h1, h2]
  exact ⟨hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num)),
    hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num)),
    hr 10 _ (by norm_num) (by norm_num) (by norm_num at hb ⊢; omega)⟩

/-- The native limbs returned by the production balanced-piece gates equal
the constructed bounded slope element. Thus these are usable in the actual
comb/ladder constraints, rather than only existential mathematical slopes. -/
theorem slopePieces_limb (l : Fp) (i : Fin 8) :
    (slopeElem l).limbs.get i =
      (slopePieces l).get ⟨3 * i.val, by omega⟩ +
      (slopePieces l).get ⟨3 * i.val + 1, by omega⟩ * 2048 +
      (slopePieces l).get ⟨3 * i.val + 2, by omega⟩ * 4194304 - 2147483648 := by
  have h0 := slopePieces_get l i 0
  have h1 := slopePieces_get l i 1
  have h2 := slopePieces_get l i 2
  simp only [Fin.val_zero, Fin.val_one, Fin.val_two, Nat.add_zero, if_true,
    show (1 : ℕ) ≠ 0 by decide, show (2 : ℕ) ≠ 0 by decide,
    show (2 : ℕ) ≠ 1 by decide, if_false] at h0 h1 h2
  rw [h0, h1, h2]
  rw [slopeElem, mkElem_limb]
  rw [show signedSlopeInts l i = (unsignedSlopeLimb l i : ℤ) - 2 ^ 31 from rfl]
  simp only [Int.cast_sub, Int.cast_natCast, Int.cast_pow, Int.cast_ofNat]
  change ((unsignedSlopeLimb l i : ℕ) : F) - (2 : F) ^ 31 = _
  have he := congrArg (fun v : ℕ => (v : F)) (pieces3_recompose (unsignedSlopeLimb l i))
  push_cast at he
  norm_num
  linear_combination he

end ZolanaVE.P256.Completeness
