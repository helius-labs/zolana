import VerifiableEncryption.Aes.Spec
import VerifiableEncryption.Aes.Spread

namespace ZolanaVE.Aes

/-- Byte `j` of the region-`r` substitution word: the MixColumns coefficient of
row `j` for input row `r`, so the `RotateLeft32` by `8 r` is absorbed here. -/
def mixByte (r j : Fin 4) (s : Byte) : Byte :=
  match (j.val + 4 - r.val) % 4 with
  | 0 => xtime s
  | 1 => s
  | 2 => s
  | _ => mul3 s

def substitutionEntry (r : ℕ) (a : ℕ) : ℕ :=
  if r = 4 then spread8 (sb (BitVec.ofNat 8 a))
  else spreadWord (fun j => mixByte (Fin.ofNat' 4 r) j (sb (BitVec.ofNat 8 a)))

/-- Entry `i` of the 1280-entry substitution lookup table, regions concatenated
in insertion order. -/
def substitutionAt (i : ℕ) : ℕ := (AesTables.substitution.getD (i / 256) []).getD (i % 256) 0

theorem substitution0_eq : AesTables.substitution0 = (List.range 256).map (substitutionEntry 0) := by
  decide +kernel

theorem substitution1_eq : AesTables.substitution1 = (List.range 256).map (substitutionEntry 1) := by
  decide +kernel

theorem substitution2_eq : AesTables.substitution2 = (List.range 256).map (substitutionEntry 2) := by
  decide +kernel

theorem substitution3_eq : AesTables.substitution3 = (List.range 256).map (substitutionEntry 3) := by
  decide +kernel

theorem substitution4_eq : AesTables.substitution4 = (List.range 256).map (substitutionEntry 4) := by
  decide +kernel

theorem sboxTable_eq : AesTables.sboxTable = (List.range 256).map (fun a => (sb (BitVec.ofNat 8 a)).toNat) := by
  decide +kernel

theorem substitution_spec (r : Fin 5) (a : Byte) :
    substitutionAt (a.toNat + 256 * r.val) =
      if r.val = 4 then spread8 (sb a) else spreadWord (fun j => mixByte (Fin.ofNat' 4 r.val) j (sb a)) := by
  have ha := a.isLt
  have hdiv : (a.toNat + 256 * r.val) / 256 = r.val := by omega
  have hmod : (a.toNat + 256 * r.val) % 256 = a.toNat := by omega
  have hentry : ∀ l : List ℕ, l = (List.range 256).map (substitutionEntry r.val) →
      l.getD a.toNat 0 = if r.val = 4 then spread8 (sb a)
        else spreadWord (fun j => mixByte (Fin.ofNat' 4 r.val) j (sb a)) := by
    intro l hl
    rw [hl, getD_map_range ha, substitutionEntry, BitVec.ofNat_toNat, BitVec.setWidth_eq]
  unfold substitutionAt
  rw [hdiv, hmod]
  match r with
  | ⟨0, _⟩ => exact hentry _ substitution0_eq
  | ⟨1, _⟩ => exact hentry _ substitution1_eq
  | ⟨2, _⟩ => exact hentry _ substitution2_eq
  | ⟨3, _⟩ => exact hentry _ substitution3_eq
  | ⟨4, _⟩ => exact hentry _ substitution4_eq

theorem substitution_mix_spec (r : Fin 4) (a : Byte) :
    substitutionAt (a.toNat + 256 * r.val) = spreadWord (fun j => mixByte r j (sb a)) := by
  have h := substitution_spec ⟨r.val, by omega⟩ a
  have hr : r.val ≠ 4 := by omega
  have hfin : Fin.ofNat' 4 r.val = r := Fin.ext (by simp [Fin.ofNat', Nat.mod_eq_of_lt r.isLt])
  simp only [hr, if_false, hfin] at h
  exact h

theorem substitution_sbox_spec (a : Byte) : substitutionAt (a.toNat + 256 * 4) = spread8 (sb a) :=
  substitution_spec 4 a

theorem sbox_eq (a : Byte) : AesTables.sboxTable.getD a.toNat 0 = (sb a).toNat := by
  rw [sboxTable_eq, getD_map_range a.isLt, BitVec.ofNat_toNat, BitVec.setWidth_eq]

end ZolanaVE.Aes
