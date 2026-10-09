import VerifiableEncryption.Aes.Lookups
import VerifiableEncryption.Aes.Ctr

/-!
The extracted AES step gadgets imply the hand mirrors of `Round.lean`, and
through them byte-level statements against `Spec.lean`. Every lemma is in
continuation form: a satisfied gadget `G args k` yields `k` at the specified
outputs.
-/

namespace ZolanaVE.Aes

open ZolanaVE

variable [Fact (Nat.Prime Order)]

theorem sum_chunks8 (f : Fin (2 * 4) → F) :
    ∑ q : Fin (2 * 4), f q * (1296 : F) ^ q.val =
      f 0 + f 1 * 1296 + f 2 * 1296 ^ 2 + f 3 * 1296 ^ 3 + f 4 * 1296 ^ 4 + f 5 * 1296 ^ 5 +
        f 6 * 1296 ^ 6 + f 7 * 1296 ^ 7 := by
  rw [Fin.sum_univ_eight]
  norm_num
  rfl

theorem sum_chunks2 (f : Fin (2 * 1) → F) : ∑ q : Fin (2 * 1), f q * (1296 : F) ^ q.val = f 0 + f 1 * 1296 := by
  rw [Fin.sum_univ_two]
  norm_num

theorem decodeWord4_mirror (hL : AesLookupSem) {S : F} {k : List.Vector F 4 → Prop}
    (h : AesDecodeWord_4 S k) :
    ∃ chunks nibbles : Fin (2 * 4) → F, ∃ bytes : Fin 4 → F,
      DecodeWord chunkRel 4 S chunks nibbles bytes ∧ k (List.Vector.ofFn bytes) := by
  unfold AesDecodeWord_4 at h
  simp only [exists_eq_left, gate_add, gate_mul, gate_eq] at h
  obtain ⟨c, hsum, h⟩ := h
  obtain ⟨n0, h0, h⟩ := chunk_step hL.chunk h
  obtain ⟨n1, h1, h⟩ := chunk_step hL.chunk h
  obtain ⟨n2, h2, h⟩ := chunk_step hL.chunk h
  obtain ⟨n3, h3, h⟩ := chunk_step hL.chunk h
  obtain ⟨n4, h4, h⟩ := chunk_step hL.chunk h
  obtain ⟨n5, h5, h⟩ := chunk_step hL.chunk h
  obtain ⟨n6, h6, h⟩ := chunk_step hL.chunk h
  obtain ⟨n7, h7, h⟩ := chunk_step hL.chunk h
  refine ⟨fun q => c.get q, ![n0, n1, n2, n3, n4, n5, n6, n7],
    ![n0 + n1 * 16, n2 + n3 * 16, n4 + n5 * 16, n6 + n7 * 16], ⟨?_, ?_, ?_⟩, ?_⟩
  · rw [hsum, sum_chunks8 (fun q => c.get q)]
    simp only [K_6281]
    norm_num
  · intro q
    fin_cases q <;> assumption
  · intro j
    fin_cases j <;> rfl
  · convert h using 1

theorem decodeWord1_mirror (hL : AesLookupSem) {S : F} {k : List.Vector F 1 → Prop}
    (h : AesDecodeWord_1 S k) :
    ∃ chunks nibbles : Fin (2 * 1) → F, ∃ bytes : Fin 1 → F,
      DecodeWord chunkRel 1 S chunks nibbles bytes ∧ k (List.Vector.ofFn bytes) := by
  unfold AesDecodeWord_1 at h
  simp only [exists_eq_left, gate_add, gate_mul, gate_eq] at h
  obtain ⟨c, hsum, h⟩ := h
  obtain ⟨n0, h0, h⟩ := chunk_step hL.chunk h
  obtain ⟨n1, h1, h⟩ := chunk_step hL.chunk h
  refine ⟨fun q => c.get q, ![n0, n1], ![n0 + n1 * 16], ⟨?_, ?_, ?_⟩, ?_⟩
  · rw [hsum, sum_chunks2 (fun q => c.get q)]
    norm_num
  · intro q
    fin_cases q <;> assumption
  · intro j
    fin_cases j
    rfl
  · convert h using 1

theorem decodeWord4_cps (hL : AesLookupSem) {kk : ℕ} (hk : kk ≤ 5) (b : Fin 4 → Fin kk → Byte)
    {S : F} (hS : S = ∑ j : Fin 4, (∑ t, (spread8 (b j t) : F)) * ((6 : F) ^ 8) ^ j.val)
    {k : List.Vector F 4 → Prop} (h : AesDecodeWord_4 S k) :
    k (List.Vector.ofFn fun j => ((xorAll (b j)).toNat : F)) := by
  obtain ⟨chunks, nibbles, bytes, hdec, hk'⟩ := decodeWord4_mirror hL h
  have := decodeWord_xor order_gt le_rfl hk b chunkRel_sound hS hdec
  convert hk' using 2
  funext j
  exact (this j).symm

theorem decodeWord1_cps (hL : AesLookupSem) {kk : ℕ} (hk : kk ≤ 5) (b : Fin kk → Byte)
    {S : F} (hS : S = ∑ t, (spread8 (b t) : F)) {k : List.Vector F 1 → Prop}
    (h : AesDecodeWord_1 S k) : k (List.Vector.ofFn fun _ => ((xorAll b).toNat : F)) := by
  obtain ⟨chunks, nibbles, bytes, hdec, hk'⟩ := decodeWord1_mirror hL h
  have := decodeWord_xor order_gt (by norm_num) hk (fun _ => b) chunkRel_sound
    (by rw [hS]; simp) hdec
  convert hk' using 2
  funext j
  exact (this j).symm

theorem roundColumn_cps (hL : AesLookupSem) (s rk : Fin 4 → Byte) {State RK : List.Vector F 4}
    (hst : ∀ r, State.get r = ((s r).toNat : F)) (hrk : ∀ j, RK.get j = (spread8 (rk j) : F))
    {k : List.Vector F 4 → Prop} (h : AesRoundColumn_4_4 State RK k) :
    k (List.Vector.ofFn fun j => ((mixColumn (fun r => sb (s r)) j ^^^ rk j).toNat : F)) := by
  unfold AesRoundColumn_4_4 at h
  simp only [exists_eq_left, gate_add, gate_mul] at h
  have h := subst_step hL.subst 0 (s 0) (hst 0) (by norm_num) h
  have h := subst_step hL.subst 1 (s 1) (hst 1) (by norm_num) h
  have h := subst_step hL.subst 2 (s 2) (hst 2) (by norm_num) h
  have h := subst_step hL.subst 3 (s 3) (hst 3)
    (by rw [show ((3 : Fin 4) : ℕ) = 3 from rfl]; norm_num) h
  let b : Fin 4 → Fin 5 → Byte := fun j =>
    ![rk j, mixByte 0 j (sb (s 0)), mixByte 1 j (sb (s 1)), mixByte 2 j (sb (s 2)),
      mixByte 3 j (sb (s 3))]
  have h := decodeWord4_cps hL (by norm_num) b ?_ h
  · convert h using 2
    funext j
    congr 2
    simp only [b, xorAll_five, mixColumn_eq_mixBytes]
    ac_rfl
  · have h3 : ((3 : Fin 4) : ℕ) = 3 := rfl
    rw [hrk 0, hrk 1, hrk 2, hrk 3]
    simp only [spreadWord, Fin.sum_univ_four, Fin.sum_univ_five, b]
    simp [h3]
    ring

theorem counterByte_cps (hL : AesLookupSem) (key : Byte) {SK : F} (hsk : SK = (spread8 key : F))
    {k : F → Prop} (h : AesCounterByte_2 SK k) : k ((key ^^^ 2#8).toNat : F) := by
  unfold AesCounterByte_2 at h
  simp only [exists_eq_left, gate_add, gate_mul] at h
  have h := decodeWord1_cps hL (by norm_num) ![key, 2#8] ?_ h
  · simpa [xorAll_two] using h
  · rw [hsk]
    simp only [Fin.sum_univ_two]
    have : spread8 2#8 = 6 := by decide
    simp [this]

theorem finalRound_cps (hL : AesLookupSem) (st rk pt : Fin 16 → Byte)
    {State RK PT : List.Vector F 16} (hst : ∀ i, State.get i = ((st i).toNat : F))
    (hrk : ∀ i, RK.get i = (spread8 (rk i) : F)) (hpt : ∀ i, PT.get i = (spread8 (pt i) : F))
    {k : List.Vector F 16 → Prop} (h : AesFinalRound_16_16_16 State RK PT k) :
    k (List.Vector.ofFn fun i =>
      ((sb (st (columnSource (columnOf i) (rowOf i))) ^^^ rk i ^^^ pt i).toNat : F)) := by
  unfold AesFinalRound_16_16_16 at h
  simp only [exists_eq_left, gate_add, gate_mul] at h
  have h := sbox_step hL.subst (st 0) (hst 0) (by norm_num) h
  have h := sbox_step hL.subst (st 5) (hst 5) (by norm_num) h
  have h := sbox_step hL.subst (st 10) (hst 10) (by norm_num) h
  have h := sbox_step hL.subst (st 15) (hst 15) (by norm_num) h
  have h := sbox_step hL.subst (st 4) (hst 4) (by norm_num) h
  have h := sbox_step hL.subst (st 9) (hst 9) (by norm_num) h
  have h := sbox_step hL.subst (st 14) (hst 14) (by norm_num) h
  have h := sbox_step hL.subst (st 3) (hst 3) (by norm_num) h
  have h := sbox_step hL.subst (st 8) (hst 8) (by norm_num) h
  have h := sbox_step hL.subst (st 13) (hst 13) (by norm_num) h
  have h := sbox_step hL.subst (st 2) (hst 2) (by norm_num) h
  have h := sbox_step hL.subst (st 7) (hst 7) (by norm_num) h
  have h := sbox_step hL.subst (st 12) (hst 12) (by norm_num) h
  have h := sbox_step hL.subst (st 1) (hst 1) (by norm_num) h
  have h := sbox_step hL.subst (st 6) (hst 6) (by norm_num) h
  have h := sbox_step hL.subst (st 11) (hst 11) (by norm_num) h
  have h := decodeWord4_cps hL (by norm_num)
    (fun j => ![sb (st (columnSource 0 j)), rk (stateIndex 0 j), pt (stateIndex 0 j)]) ?_ h
  · have h := decodeWord4_cps hL (by norm_num)
      (fun j => ![sb (st (columnSource 1 j)), rk (stateIndex 1 j), pt (stateIndex 1 j)]) ?_ h
    · have h := decodeWord4_cps hL (by norm_num)
        (fun j => ![sb (st (columnSource 2 j)), rk (stateIndex 2 j), pt (stateIndex 2 j)]) ?_ h
      · have h := decodeWord4_cps hL (by norm_num)
          (fun j => ![sb (st (columnSource 3 j)), rk (stateIndex 3 j), pt (stateIndex 3 j)]) ?_ h
        · convert h using 1
          apply List.Vector.ext
          intro i
          fin_cases i <;> simp [xorAll_three] <;> rfl
        · rw [hrk 12, hrk 13, hrk 14, hrk 15, hpt 12, hpt 13, hpt 14, hpt 15]
          simp [Fin.sum_univ_four, Fin.sum_univ_three]
          rfl
      · rw [hrk 8, hrk 9, hrk 10, hrk 11, hpt 8, hpt 9, hpt 10, hpt 11]
        simp [Fin.sum_univ_four, Fin.sum_univ_three]
        rfl
    · rw [hrk 4, hrk 5, hrk 6, hrk 7, hpt 4, hpt 5, hpt 6, hpt 7]
      simp [Fin.sum_univ_four, Fin.sum_univ_three]
      rfl
  · rw [hrk 0, hrk 1, hrk 2, hrk 3, hpt 0, hpt 1, hpt 2, hpt 3]
    simp [Fin.sum_univ_four, Fin.sum_univ_three]
    rfl

end ZolanaVE.Aes
