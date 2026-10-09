import VerifiableEncryption.Curve.CombLimbs
import VerifiableEncryption.Curve.Comb
import VerifiableEncryption.Curve.CombSelect
import VerifiableEncryption.Curve.ChainStep

/-!
The constant comb tables of the extracted circuit, matched entry by entry
against the certified `CombTables` points.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks ZolanaVE.CombLimbs ZolanaVE.P256.Comb

def txAt (t : ℕ) : List.Vector (List.Vector F 8) 32 :=
  txs.getD t (List.Vector.replicate 32 (List.Vector.replicate 8 0))

def tyAt (t : ℕ) : List.Vector (List.Vector F 3) 32 :=
  tys.getD t (List.Vector.replicate 32 (List.Vector.replicate 3 0))

def topEntry (i : ℕ) : ℕ × ℕ := if i < 2 then topAt i else entry 51 (i - 2)

theorem tx_ok : ∀ t : Fin 51, ∀ i : Fin 32, ∀ l : Fin 8,
    ((txAt t).get i).get l = (((entry t i).1 / 2 ^ (32 * l.val) % 2 ^ 32 : ℕ) : F) := by
  decide +kernel

theorem ty_ok : ∀ t : Fin 51, ∀ i : Fin 32, ∀ g : Fin 3,
    ((tyAt t).get i).get g = (((entry t i).2 / 2 ^ (96 * g.val) % 2 ^ 96 : ℕ) : F) := by
  decide +kernel

theorem topX_ok : ∀ i : Fin 4, ∀ l : Fin 8,
    (topX.get i).get l = (((topEntry i).1 / 2 ^ (32 * l.val) % 2 ^ 32 : ℕ) : F) := by
  decide +kernel

theorem topY_ok : ∀ i : Fin 4, ∀ l : Fin 8,
    (topY.get i).get l = (((topEntry i).2 / 2 ^ (32 * l.val) % 2 ^ 32 : ℕ) : F) := by
  decide +kernel

/-- 32-bit limbs of a residue. -/
def xInts (v : ℕ) (l : Fin 8) : ℤ := ((v / 2 ^ (32 * l.val) % 2 ^ 32 : ℕ) : ℤ)

/-- The packed y layout: 96-bit groups at limbs 0, 3 and 6. -/
def yInts (v : ℕ) (l : Fin 8) : ℤ :=
  [((v % 2 ^ 96 : ℕ) : ℤ), 0, 0, ((v / 2 ^ 96 % 2 ^ 96 : ℕ) : ℤ), 0, 0, ((v / 2 ^ 192 % 2 ^ 96 : ℕ) : ℤ), 0].getD l 0

theorem rec8_xInts {v : ℕ} (hv : v < 2 ^ 256) : rec8 (xInts v) = v := by
  simp only [rec8, xInts, Fin.isValue, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, Nat.reduceMul,
    Nat.reducePow]
  push_cast
  omega

theorem rec8_yInts {v : ℕ} (hv : v < 2 ^ 256) : rec8 (yInts v) = v := by
  simp only [rec8, yInts, Fin.isValue, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, List.getD_cons_succ,
    List.getD_cons_zero]
  norm_num
  omega

theorem xInts_fits {v : ℕ} (hv : v < 2 ^ 256) : Fits (xInts v) reducedC := by
  apply fits_uni
  · intro l
    simp only [xInts]
    constructor
    · positivity
    · have := Nat.mod_lt (v / 2 ^ (32 * l.val)) (show 0 < 2 ^ 32 by norm_num)
      omega
  · rw [rec8_xInts hv]
    constructor
    · positivity
    · have : (v : ℤ) < 2 ^ 256 := by exact_mod_cast hv
      linarith

theorem packC_eq : packC = ⟨[0, 0, 0, 0, 0, 0, 0, 0],
    [2 ^ 96 - 1, 0, 0, 2 ^ 96 - 1, 0, 0, 2 ^ 64 - 1, 0], 0, 2 ^ 256 - 1⟩ := by
  rfl

theorem yInts_fits {v : ℕ} (hv : v < 2 ^ 256) : Fits (yInts v) packC := by
  rw [packC_eq]
  refine ⟨rfl, rfl, fun l => ?_, ?_, ?_⟩
  · fin_cases l <;>
      simp only [yInts, Fin.isValue, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, List.getD_cons_succ,
        List.getD_cons_zero, Fin.mk_zero, Fin.zero_eta, Fin.mk_one] <;>
      norm_num <;> omega
  · rw [rec8_yInts hv]; show (0 : ℤ) ≤ v; positivity
  · rw [rec8_yInts hv]
    show (v : ℤ) ≤ 2 ^ 256 - 1
    have : (v : ℤ) < 2 ^ 256 := by exact_mod_cast hv
    linarith

def winX (v : ℕ) (hv : v < 2 ^ 256) : ElemVal 8 := mkElem (xInts v) reducedC (xInts_fits hv)
def winY (v : ℕ) (hv : v < 2 ^ 256) : ElemVal 8 := mkElem (yInts v) packC (yInts_fits hv)

theorem p_lt_two_pow : p < 2 ^ 256 := by decide +kernel

end ZolanaVE.P256
