import VerifiableEncryption.Aes.KeyExpansion
import VerifiableEncryption.Aes.Block

/-!
Spec-side facts the extracted CTR block is matched against: round keys as
offsets into the 240 round-key bytes, the bytes of the first state for counter
2, and one output byte of `encryptBlock`. Every statement is over an arbitrary
key schedule `w`, so no proof here unfolds `keyExpansion256`.
-/

namespace ZolanaVE.Aes

open ZolanaVE

def bytesOf {m : ℕ} (v : List.Vector F m) : Fin m → Byte := fun n => BitVec.ofNat 8 (v.get n).val

theorem roundKey_eq_rkByte (w : Fin 60 → Word) (r : Fin 15) :
    roundKey w r = fun i => rkByte w ⟨16 * r.val + i.val, by omega⟩ := by
  funext i
  have h1 : (⟨4 * r.val + (col i).val, by omega⟩ : Fin 60) =
      ⟨(16 * r.val + i.val) / 4, by omega⟩ := Fin.ext (by simp only [col]; omega)
  have h2 : row i = ⟨(16 * r.val + i.val) % 4, by omega⟩ := Fin.ext (by simp only [row]; omega)
  simp only [roundKey, rkByte]
  rw [h1, h2]

theorem state0_eq (w : Fin 60 → Word) (nonce : Fin 12 → Byte) (i : Fin 16) :
    roundsFrom w (counterBlock nonce 2) 0 i =
      counterBlock nonce 2 i ^^^ rkByte w ⟨i.val, by omega⟩ := by
  rw [roundsFrom, addRoundKey, roundKey_eq_rkByte]
  have hi : (⟨16 * (0 : Fin 15).val + i.val, by omega⟩ : Fin 240) = ⟨i.val, by omega⟩ :=
    Fin.ext (by simp)
  simp only [hi]

theorem state0_nonce (w : Fin 60 → Word) (nonce : Fin 12 → Byte) (i : ℕ) (hi : i < 12) :
    roundsFrom w (counterBlock nonce 2) 0 ⟨i, by omega⟩ = nonce ⟨i, hi⟩ ^^^ rkByte w ⟨i, by omega⟩ := by
  rw [state0_eq]
  simp only [counterBlock, dif_pos hi]

theorem state0_12 (w : Fin 60 → Word) (nonce : Fin 12 → Byte) :
    roundsFrom w (counterBlock nonce 2) 0 ⟨12, by norm_num⟩ = rkByte w ⟨12, by norm_num⟩ := by
  rw [state0_eq]
  simp [counterBlock, be32]

theorem state0_13 (w : Fin 60 → Word) (nonce : Fin 12 → Byte) :
    roundsFrom w (counterBlock nonce 2) 0 ⟨13, by norm_num⟩ = rkByte w ⟨13, by norm_num⟩ := by
  rw [state0_eq]
  simp [counterBlock, be32]

theorem state0_14 (w : Fin 60 → Word) (nonce : Fin 12 → Byte) :
    roundsFrom w (counterBlock nonce 2) 0 ⟨14, by norm_num⟩ = rkByte w ⟨14, by norm_num⟩ := by
  rw [state0_eq]
  simp [counterBlock, be32]

theorem state0_15 (w : Fin 60 → Word) (nonce : Fin 12 → Byte) :
    roundsFrom w (counterBlock nonce 2) 0 ⟨15, by norm_num⟩ = rkByte w ⟨15, by norm_num⟩ ^^^ 2#8 := by
  rw [state0_eq, BitVec.xor_comm]
  simp [counterBlock, be32]

theorem rounds_step (w : Fin 60 → Word) (blk : Block) (n : ℕ) (hn : n < 13) :
    roundsFrom w blk (n + 1) =
      fullRound (roundsFrom w blk n) (fun i => rkByte w ⟨16 * (n + 1) + i.val, by omega⟩) := by
  rw [roundsFrom_succ w blk n hn, roundKey_eq_rkByte]

theorem encryptBlock_byte (key : Fin 32 → Byte) (blk : Block) (i : Fin 16) :
    encryptBlock key blk i =
      sb (roundsFrom (keyExpansion256 key) blk 13 (columnSource (columnOf i) (rowOf i))) ^^^
        rkByte (keyExpansion256 key) ⟨16 * 14 + i.val, by omega⟩ := by
  rw [encryptBlock, encryptWith, finalRound_eq, addRoundKey, roundKey_eq_rkByte]
  rfl

theorem vec2_get0 {α : Type} (a b : α) : (vec![a, b] : List.Vector α 2).get 0 = a := rfl

theorem vec2_get1 {α : Type} (a b : α) : (vec![a, b] : List.Vector α 2).get 1 = b := rfl

variable [Fact (Nat.Prime Order)]

theorem nonceWord_cps (hL : AesLookupSem) (w : Fin 60 → Word) (nonce : Fin 12 → Byte) (g : ℕ)
    (hg : g < 3) {z0 z1 z2 z3 : F}
    (hz0 : z0 = Gates.add (spread8 (nonce ⟨4 * g, by omega⟩) : F) (spread8 (rkByte w ⟨4 * g, by omega⟩) : F))
    (hz1 : z1 = Gates.add (spread8 (nonce ⟨4 * g + 1, by omega⟩) : F)
      (spread8 (rkByte w ⟨4 * g + 1, by omega⟩) : F))
    (hz2 : z2 = Gates.add (spread8 (nonce ⟨4 * g + 2, by omega⟩) : F)
      (spread8 (rkByte w ⟨4 * g + 2, by omega⟩) : F))
    (hz3 : z3 = Gates.add (spread8 (nonce ⟨4 * g + 3, by omega⟩) : F)
      (spread8 (rkByte w ⟨4 * g + 3, by omega⟩) : F))
    {k : List.Vector F 4 → Prop}
    (h : ∃ g0, g0 = Gates.mul z0 (1 : F) ∧ ∃ g1, g1 = Gates.add (0 : F) g0 ∧
      ∃ g2, g2 = Gates.mul z1 (1679616 : F) ∧ ∃ g3, g3 = Gates.add g1 g2 ∧
      ∃ g4, g4 = Gates.mul z2 (2821109907456 : F) ∧ ∃ g5, g5 = Gates.add g3 g4 ∧
      ∃ g6, g6 = Gates.mul z3 (4738381338321616896 : F) ∧ ∃ g7, g7 = Gates.add g5 g6 ∧
      AesDecodeWord_4 g7 k) :
    k (colVec (roundsFrom w (counterBlock nonce 2) 0) ⟨g, by omega⟩) := by
  have h := packDecode_cps hL (by norm_num)
    (fun j => ![nonce ⟨4 * g + j.val, by omega⟩, rkByte w ⟨4 * g + j.val, by omega⟩])
    (by rw [hz0, gate_add]; simp [Fin.sum_univ_two])
    (by rw [hz1, gate_add]; simp [Fin.sum_univ_two])
    (by rw [hz2, gate_add]; simp [Fin.sum_univ_two])
    (by rw [hz3, gate_add]; simp [Fin.sum_univ_two, show ((3 : Fin 4) : ℕ) = 3 from rfl]) h
  convert h using 1
  unfold colVec
  congr 1
  funext j
  rw [xorAll_two]
  have hidx : stateIndex ⟨g, by omega⟩ j = ⟨4 * g + j.val, by omega⟩ := Fin.ext (by simp [stateIndex])
  rw [hidx, state0_nonce w nonce (4 * g + j.val) (by omega)]

end ZolanaVE.Aes
