import VerifiableEncryption.Aes.Gadgets
import VerifiableEncryption.Aes.KeySpec

/-!
Continuation-form steps for one word of the extracted `AesKeyExpansion_32`:
the S-box lookups of the previous word, the round-constant addition, and the
decoded XOR with the word eight positions back followed by its spread lookups.
-/

namespace ZolanaVE.Aes

open ZolanaVE

variable [Fact (Nat.Prime Order)]

def wordVec (R : Word) : List.Vector F 4 := List.Vector.ofFn fun j => ((R j).toNat : F)

theorem spread8_zero' : spread8 (0 : Byte) = 0 := by decide

theorem let_step {v : F} {k : F → Prop} (h : ∃ g, g = v ∧ k g) : k v := by
  obtain ⟨_, rfl, h⟩ := h
  exact h

theorem keyByte_step (hL : AesLookupSem) {a : F} {k : F → Prop} (h : SpreadByteLookup a k) :
    a = ((BitVec.ofNat 8 a.val).toNat : F) ∧ k (spread8 (BitVec.ofNat 8 a.val) : F) := by
  obtain ⟨ha, hk⟩ := hL.spread a k h
  have hab : a = ((BitVec.ofNat 8 a.val).toNat : F) := by
    rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt ha, ZMod.natCast_zmod_val]
  refine ⟨hab, ?_⟩
  rw [bytesTable_spec _ ha] at hk
  convert hk using 3
  rw [spread8, BitVec.toNat_ofNat, Nat.mod_eq_of_lt ha]

theorem sboxLet_step (hL : AesLookupSem) (b : Byte) {a : F} (hab : a = (b.toNat : F))
    {k : F → Prop} (h : ∃ g, g = Gates.add a (1024 : F) ∧ SubstitutionLookup g k) :
    k (spread8 (sb b) : F) := by
  obtain ⟨g, hg, h⟩ := h
  exact sbox_step hL.subst b hab (by rw [hg, gate_add]; norm_num) h

theorem spreadWord_step (hL : AesLookupSem) (R : Word) {k : F → F → F → F → Prop}
    (h : SpreadByteLookup ((wordVec R).get 0) fun s0 => SpreadByteLookup ((wordVec R).get 1) fun s1 =>
      SpreadByteLookup ((wordVec R).get 2) fun s2 => SpreadByteLookup ((wordVec R).get 3) fun s3 =>
        k s0 s1 s2 s3) :
    k (spread8 (R 0)) (spread8 (R 1)) (spread8 (R 2)) (spread8 (R 3)) := by
  have h := spreadByte_step_of hL.spread (R 0) (by simp [wordVec]) h
  have h := spreadByte_step_of hL.spread (R 1) (by simp [wordVec]) h
  have h := spreadByte_step_of hL.spread (R 2) (by simp [wordVec]) h
  exact spreadByte_step_of hL.spread (R 3) (by simp [wordVec]) h

theorem keyWord_cps (hL : AesLookupSem) (A B C R : Word) {x0 x1 x2 x3 y0 y1 y2 y3 : F}
    (hx0 : x0 = (spread8 (A 0) : F)) (hx1 : x1 = (spread8 (A 1) : F))
    (hx2 : x2 = (spread8 (A 2) : F)) (hx3 : x3 = (spread8 (A 3) : F))
    (hy0 : y0 = (spread8 (B 0) : F) + (spread8 (C 0) : F))
    (hy1 : y1 = (spread8 (B 1) : F) + (spread8 (C 1) : F))
    (hy2 : y2 = (spread8 (B 2) : F) + (spread8 (C 2) : F))
    (hy3 : y3 = (spread8 (B 3) : F) + (spread8 (C 3) : F))
    (hR : ∀ j, A j ^^^ B j ^^^ C j = R j)
    {k : List.Vector F 4 → F → F → F → F → Prop}
    (h : ∃ g0, g0 = Gates.add x0 y0 ∧ ∃ g1, g1 = Gates.add x1 y1 ∧
      ∃ g2, g2 = Gates.add x2 y2 ∧ ∃ g3, g3 = Gates.add x3 y3 ∧
      ∃ g4, g4 = Gates.mul g0 (1 : F) ∧ ∃ g5, g5 = Gates.add (0 : F) g4 ∧
      ∃ g6, g6 = Gates.mul g1 (1679616 : F) ∧ ∃ g7, g7 = Gates.add g5 g6 ∧
      ∃ g8, g8 = Gates.mul g2 (2821109907456 : F) ∧ ∃ g9, g9 = Gates.add g7 g8 ∧
      ∃ g10, g10 = Gates.mul g3 (4738381338321616896 : F) ∧ ∃ g11, g11 = Gates.add g9 g10 ∧
      AesDecodeWord_4 g11 fun w =>
        SpreadByteLookup (w.get 0) fun s0 => SpreadByteLookup (w.get 1) fun s1 =>
        SpreadByteLookup (w.get 2) fun s2 => SpreadByteLookup (w.get 3) fun s3 =>
          k w s0 s1 s2 s3) :
    k (wordVec R) (spread8 (R 0)) (spread8 (R 1)) (spread8 (R 2)) (spread8 (R 3)) := by
  simp only [exists_eq_left, gate_add, gate_mul] at h
  have h := decodeWord4_cps hL (by norm_num) (fun j => ![A j, B j, C j]) ?_ h
  · have hv : (List.Vector.ofFn fun j => ((xorAll ![A j, B j, C j]).toNat : F)) = wordVec R := by
      unfold wordVec
      congr
      funext j
      rw [xorAll_three, hR]
    rw [hv] at h
    exact spreadWord_step hL R h
  · have h3 : ((3 : Fin 4) : ℕ) = 3 := rfl
    rw [hx0, hx1, hx2, hx3, hy0, hy1, hy2, hy3]
    simp [Fin.sum_univ_four, Fin.sum_univ_three, h3]
    ring

end ZolanaVE.Aes
