import Mathlib.Tactic
import VerifiableEncryption.Aes.Spec

/-!
Word recurrences of `keyExpansion256`, by byte, in the three shapes the circuit
computes them.
-/

namespace ZolanaVE.Aes

theorem keyWords_length (key : Fin 32 → Byte) : ∀ n, (keyWords key n).length = n
  | 0 => rfl
  | n + 1 => by simp [keyWords, keyWords_length key n]

theorem keyWords_getD_mono (key : Fin 32 → Byte) {i n : ℕ} (hi : i < n) :
    ∀ m, n ≤ m → (keyWords key m).getD i zeroWord = (keyWords key n).getD i zeroWord := by
  intro m hm
  induction m, hm using Nat.le_induction with
  | base => rfl
  | succ m hm ih =>
    rw [keyWords, List.getD_eq_getElem?_getD, List.getElem?_append_left
      (by rw [keyWords_length]; omega), ← List.getD_eq_getElem?_getD, ih]

theorem keyWords_getD_self (key : Fin 32 → Byte) (n : ℕ) :
    (keyWords key (n + 1)).getD n zeroWord = nextKeyWord key (keyWords key n) n := by
  rw [keyWords, List.getD_eq_getElem?_getD, List.getElem?_append_right
    (by rw [keyWords_length]), keyWords_length]
  simp

theorem keyWords_getD_eq (key : Fin 32 → Byte) {i n : ℕ} (hi : i < n) (hn : n ≤ 60) :
    (keyWords key n).getD i zeroWord = keyExpansion256 key ⟨i, by omega⟩ := by
  unfold keyExpansion256
  rw [keyWords_getD_mono key hi 60 hn]

theorem keyExpansion256_next (key : Fin 32 → Byte) (i : ℕ) (hi : i < 60) :
    keyExpansion256 key ⟨i, hi⟩ = nextKeyWord key (keyWords key i) i := by
  unfold keyExpansion256
  rw [keyWords_getD_mono key (Nat.lt_succ_self i) 60 hi, keyWords_getD_self]

theorem keyExpansion256_lt8 (key : Fin 32 → Byte) (i : ℕ) (hi : i < 8) (j : Fin 4) :
    keyExpansion256 key ⟨i, by omega⟩ j = key ⟨4 * i + j.val, by omega⟩ := by
  rw [keyExpansion256_next key i (by omega), nextKeyWord, dif_pos hi]
  rfl

theorem keyExpansion256_rec (key : Fin 32 → Byte) (i : ℕ) (h8 : 8 ≤ i) (hi : i < 60) :
    keyExpansion256 key ⟨i, hi⟩ =
      xorWord (keyExpansion256 key ⟨i - 8, by omega⟩)
        (if i % 8 = 0 then
          xorWord (subWord (rotWord (keyExpansion256 key ⟨i - 1, by omega⟩))) (rcon (i / 8))
        else if i % 8 = 4 then subWord (keyExpansion256 key ⟨i - 1, by omega⟩)
        else keyExpansion256 key ⟨i - 1, by omega⟩) := by
  rw [keyExpansion256_next key i hi, nextKeyWord, dif_neg (by omega)]
  simp only
  rw [keyWords_getD_eq key (by omega : i - 1 < i) (by omega),
    keyWords_getD_eq key (by omega : i - 8 < i) (by omega)]

theorem keyWord_copy (key : Fin 32 → Byte) (i : ℕ) (h8 : 8 ≤ i) (hi : i < 60) (h0 : i % 8 ≠ 0)
    (h4 : i % 8 ≠ 4) (j : Fin 4) :
    keyExpansion256 key ⟨i, hi⟩ j =
      keyExpansion256 key ⟨i - 8, by omega⟩ j ^^^ keyExpansion256 key ⟨i - 1, by omega⟩ j := by
  rw [keyExpansion256_rec key i h8 hi, if_neg h0, if_neg h4]
  rfl

theorem keyWord_sub (key : Fin 32 → Byte) (i : ℕ) (h8 : 8 ≤ i) (hi : i < 60) (h4 : i % 8 = 4)
    (j : Fin 4) :
    keyExpansion256 key ⟨i, hi⟩ j =
      keyExpansion256 key ⟨i - 8, by omega⟩ j ^^^ sb (keyExpansion256 key ⟨i - 1, by omega⟩ j) := by
  rw [keyExpansion256_rec key i h8 hi, if_neg (by omega), if_pos h4]
  rfl

theorem keyWord_rot (key : Fin 32 → Byte) (i : ℕ) (h8 : 8 ≤ i) (hi : i < 60) (h0 : i % 8 = 0)
    (j : Fin 4) :
    keyExpansion256 key ⟨i, hi⟩ j =
      keyExpansion256 key ⟨i - 8, by omega⟩ j ^^^
        (sb (keyExpansion256 key ⟨i - 1, by omega⟩ (j + 1)) ^^^ rcon (i / 8) j) := by
  rw [keyExpansion256_rec key i h8 hi, if_pos h0]
  rfl

end ZolanaVE.Aes
