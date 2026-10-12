import VerifiableEncryption.Curve.CompletenessLadderInputs

/-! Construct the actual 25-entry scalar modulus-gap hint. The first 24
entries encode n-1-(original mod n) in 11/11/10-bit pieces; the last entry
is the carry between the two native 128-bit equality checks. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

def scalarGapNat (original : ℕ) : ℕ := n - 1 - original % n
def gapLow (v : ℕ) : ℕ := v % 2 ^ 128
def gapHigh (v : ℕ) : ℕ := v / 2 ^ 128
def scalarGapCarry (original : ℕ) : ℕ :=
  (gapLow (original % n) + gapLow (scalarGapNat original)) / 2 ^ 128

theorem scalarGap_sum (original : ℕ) : original % n + scalarGapNat original = n - 1 := by
  have hs := Nat.mod_lt original (show 0 < n by norm_num [n])
  unfold scalarGapNat
  omega

theorem scalarGap_width (original : ℕ) : scalarGapNat original < 2 ^ 256 := by
  have hn : scalarGapNat original < n := by
    dsimp [scalarGapNat]
    have : 0 < n := by norm_num [n]
    omega
  exact lt_trans hn n_lt_ladder_width

theorem scalarGapCarry_bounds (original : ℕ) : scalarGapCarry original ≤ 1 := by
  have hs := Nat.mod_lt (original % n) (show 0 < 2 ^ 128 by norm_num)
  have hg := Nat.mod_lt (scalarGapNat original) (show 0 < 2 ^ 128 by norm_num)
  dsimp [scalarGapCarry, gapLow]
  norm_num at hs hg ⊢
  omega

theorem scalarGap_low (original : ℕ) :
    gapLow (original % n) + gapLow (scalarGapNat original) =
      gapLow (n - 1) + 2 ^ 128 * scalarGapCarry original := by
  have hmod := congrArg (fun v : ℕ => v % 2 ^ 128) (scalarGap_sum original)
  dsimp only at hmod
  rw [Nat.add_mod] at hmod
  have he :=
    (Nat.mod_add_div (gapLow (original % n) + gapLow (scalarGapNat original)) (2 ^ 128)).symm
  change (gapLow (original % n) + gapLow (scalarGapNat original)) % 2 ^ 128 = gapLow (n - 1) at hmod
  rw [hmod] at he
  exact he

theorem scalarGap_high (original : ℕ) :
    gapHigh (original % n) + gapHigh (scalarGapNat original) + scalarGapCarry original =
      gapHigh (n - 1) := by
  have hs := Nat.mod_add_div (original % n) (2 ^ 128)
  have hg := Nat.mod_add_div (scalarGapNat original) (2 ^ 128)
  have hn := Nat.mod_add_div (n - 1) (2 ^ 128)
  have hsum := scalarGap_sum original
  have hlo := scalarGap_low original
  dsimp [gapLow, gapHigh] at hlo ⊢
  norm_num at hs hg hn hlo ⊢
  omega

def scalarGapLimb (original i : ℕ) : ℕ := scalarGapNat original / 2 ^ (32 * i) % 2 ^ 32
def scalarGapPiece (original j : ℕ) : ℕ :=
  let v := scalarGapLimb original (j / 3)
  if j % 3 = 0 then v % 2048 else if j % 3 = 1 then v / 2048 % 2048 else v / 4194304

def scalarGapHint (original : ℕ) : List.Vector F 25 :=
  List.Vector.ofFn (fun j =>
    ((if j.val = 24 then scalarGapCarry original else scalarGapPiece original j.val : ℕ) : F))

theorem scalarGapHint_piece (original : ℕ) (i : Fin 8) (j : Fin 3) :
    (scalarGapHint original).get ⟨3 * i.val + j.val, by omega⟩ =
      ((if j.val = 0 then scalarGapLimb original i % 2048 else
        if j.val = 1 then scalarGapLimb original i / 2048 % 2048 else
          scalarGapLimb original i / 4194304 : ℕ) : F) := by
  have hd : (3 * i.val + j.val) / 3 = i.val := by omega
  have hm : (3 * i.val + j.val) % 3 = j.val := by omega
  have hn : 3 * i.val + j.val ≠ 24 := by omega
  simp [scalarGapHint, scalarGapPiece, hd, hm, hn]

theorem scalarGapHint_ranges (hr : RangeComplete) (original : ℕ) (i : Fin 8) :
    RangeCheck 11 ((scalarGapHint original).get ⟨3 * i.val, by omega⟩) ∧
    RangeCheck 11 ((scalarGapHint original).get ⟨3 * i.val + 1, by omega⟩) ∧
    RangeCheck 10 ((scalarGapHint original).get ⟨3 * i.val + 2, by omega⟩) := by
  have hb : scalarGapLimb original i < 2 ^ 32 := Nat.mod_lt _ (by norm_num)
  have h0 := scalarGapHint_piece original i 0
  have h1 := scalarGapHint_piece original i 1
  have h2 := scalarGapHint_piece original i 2
  simp only [Fin.val_zero, Fin.val_one, Fin.val_two, Nat.add_zero, if_true,
    show (1 : ℕ) ≠ 0 by decide, show (2 : ℕ) ≠ 0 by decide,
    show (2 : ℕ) ≠ 1 by decide, if_false] at h0 h1 h2
  rw [h0, h1, h2]
  exact ⟨hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num)),
    hr 11 _ (by norm_num) (by norm_num) (Nat.mod_lt _ (by norm_num)),
    hr 10 _ (by norm_num) (by norm_num) (by norm_num at hb ⊢; omega)⟩

theorem scalarGapHint_carry (original : ℕ) :
    (scalarGapHint original).get 24 = (scalarGapCarry original : F) := by
  norm_num [scalarGapHint, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod]

theorem scalarGapHint_bool (original : ℕ) : Gates.is_bool ((scalarGapHint original).get 24) := by
  rw [scalarGapHint_carry]
  have hc := scalarGapCarry_bounds original
  have he : scalarGapCarry original = 0 ∨ scalarGapCarry original = 1 := by omega
  rcases he with he | he <;> simp [he, Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.is_bool]

theorem scalarGapHint_limb (original : ℕ) (i : Fin 8) :
    (canonicalNatElem (scalarGapNat original) (scalarGap_width original)).limbs.get i =
      (scalarGapHint original).get ⟨3 * i.val, by omega⟩ +
      (scalarGapHint original).get ⟨3 * i.val + 1, by omega⟩ * 2048 +
      (scalarGapHint original).get ⟨3 * i.val + 2, by omega⟩ * 4194304 := by
  have h0 := scalarGapHint_piece original i 0
  have h1 := scalarGapHint_piece original i 1
  have h2 := scalarGapHint_piece original i 2
  simp only [Fin.val_zero, Fin.val_one, Fin.val_two, Nat.add_zero, if_true,
    show (1 : ℕ) ≠ 0 by decide, show (2 : ℕ) ≠ 0 by decide,
    show (2 : ℕ) ≠ 1 by decide, if_false] at h0 h1 h2
  rw [h0, h1, h2, canonicalNatElem, winX, mkElem_limb]
  change (scalarGapLimb original i : F) = _
  have he := congrArg (fun v : ℕ => (v : F)) (pieces3_recompose (scalarGapLimb original i))
  push_cast at he
  exact he

def nativeGapLow (L : List.Vector F 8) : F :=
  L.get 0 + L.get 1 * 4294967296 + L.get 2 * K_390 + L.get 3 * K_391
def nativeGapHigh (L : List.Vector F 8) : F :=
  L.get 4 + L.get 5 * 4294967296 + L.get 6 * K_390 + L.get 7 * K_391

theorem fourLimbLow (v : ℕ) :
    v % 2 ^ 32 + (v / 2 ^ 32 % 2 ^ 32) * 2 ^ 32 +
      (v / 2 ^ 64 % 2 ^ 32) * 2 ^ 64 + (v / 2 ^ 96 % 2 ^ 32) * 2 ^ 96 = gapLow v := by
  norm_num [gapLow]
  omega

theorem fourLimbHigh (v : ℕ) (hv : v < 2 ^ 256) :
    v / 2 ^ 128 % 2 ^ 32 + (v / 2 ^ 160 % 2 ^ 32) * 2 ^ 32 +
      (v / 2 ^ 192 % 2 ^ 32) * 2 ^ 64 + (v / 2 ^ 224 % 2 ^ 32) * 2 ^ 96 = gapHigh v := by
  norm_num [gapHigh] at hv ⊢
  omega

theorem nativeGapLow_canonical (v : ℕ) (hv : v < 2 ^ 256) :
    nativeGapLow (canonicalNatElem v hv).limbs = (gapLow v : F) := by
  have he := congrArg (fun v : ℕ => (v : F)) (fourLimbLow v)
  push_cast at he
  simp only [nativeGapLow, canonicalNatElem, winX, mkElem_limb, xInts, Int.cast_natCast]
  norm_num [Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod] at he ⊢
  exact he

theorem nativeGapHigh_canonical (v : ℕ) (hv : v < 2 ^ 256) :
    nativeGapHigh (canonicalNatElem v hv).limbs = (gapHigh v : F) := by
  have he := congrArg (fun v : ℕ => (v : F)) (fourLimbHigh v hv)
  push_cast at he
  simp only [nativeGapHigh, canonicalNatElem, winX, mkElem_limb, xInts, Int.cast_natCast]
  norm_num [Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod] at he ⊢
  exact he

/-- Exact native field equations at gates 86/88 and 102 of ScalarMulChecked.
The supplied 25-entry gap hint realizes both equalities and its Boolean carry. -/
theorem scalarGap_native_checks (original : ℕ) :
    nativeGapLow (canonicalScalar original).limbs +
        nativeGapLow (canonicalNatElem (scalarGapNat original) (scalarGap_width original)).limbs =
      K_1233 + (scalarGapHint original).get 24 * K_392 ∧
    nativeGapHigh (canonicalScalar original).limbs +
        nativeGapHigh (canonicalNatElem (scalarGapNat original) (scalarGap_width original)).limbs +
        (scalarGapHint original).get 24 = K_1234 := by
  rw [canonicalScalar, nativeGapLow_canonical, nativeGapLow_canonical,
    nativeGapHigh_canonical, nativeGapHigh_canonical, scalarGapHint_carry]
  have hlo := congrArg (fun v : ℕ => (v : F)) (scalarGap_low original)
  have hhi := congrArg (fun v : ℕ => (v : F)) (scalarGap_high original)
  push_cast at hlo hhi
  norm_num [gapLow, gapHigh, n] at hlo hhi
  constructor
  · simpa only [mul_comm] using hlo
  · exact hhi

end ZolanaVE.P256.Completeness
