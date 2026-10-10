import VerifiableEncryption.Aes.CtrSpec
import VerifiableEncryption.Circuit.Top

/-!
Gadget and spec lemmas for the multi-block CTR streams inlined in the envelope
circuits: counter bytes 3 and 4, the 8-byte final round, the cached column-0
partial sum shared by all blocks, and the counter-block facts behind reusing
round-1 columns 1 to 3 across blocks.
-/

namespace ZolanaVE.Aes

open ZolanaVE

theorem counterBlock_ne15 (nonce : Fin 12 → Byte) {a b : ℕ} (ha : a < 256) (hb : b < 256)
    (i : Fin 16) (hi : i.val ≠ 15) : counterBlock nonce a i = counterBlock nonce b i := by
  unfold counterBlock
  by_cases h12 : i.val < 12
  · simp [h12]
  · simp only [h12, dite_false, be32]
    congr 1
    have hj : 3 - (i.val - 12) ≥ 1 := by omega
    have hpow : 256 ≤ 256 ^ (3 - (i.val - 12)) := by
      calc 256 = 256 ^ 1 := by norm_num
        _ ≤ 256 ^ (3 - (i.val - 12)) := Nat.pow_le_pow_right (by norm_num) hj
    rw [Nat.div_eq_of_lt (by omega), Nat.div_eq_of_lt (by omega)]

theorem counterBlock_15 (nonce : Fin 12 → Byte) {a : ℕ} (ha : a < 256) :
    counterBlock nonce a ⟨15, by norm_num⟩ = BitVec.ofNat 8 a := by
  simp [counterBlock, be32]

theorem state0_ne15 (w : Fin 60 → Word) (nonce : Fin 12 → Byte) {a b : ℕ} (ha : a < 256)
    (hb : b < 256) (i : Fin 16) (hi : i.val ≠ 15) :
    roundsFrom w (counterBlock nonce a) 0 i = roundsFrom w (counterBlock nonce b) 0 i := by
  rw [state0_eq, state0_eq, counterBlock_ne15 nonce ha hb i hi]

theorem state0_15c (w : Fin 60 → Word) (nonce : Fin 12 → Byte) {a : ℕ} (ha : a < 256) :
    roundsFrom w (counterBlock nonce a) 0 ⟨15, by norm_num⟩ =
      rkByte w ⟨15, by norm_num⟩ ^^^ BitVec.ofNat 8 a := by
  rw [state0_eq, BitVec.xor_comm, counterBlock_15 nonce ha]

theorem round1_col_eq (w : Fin 60 → Word) (nonce : Fin 12 → Byte) {a b : ℕ} (ha : a < 256)
    (hb : b < 256) (c : Fin 4) (hc : c ≠ 0) (j : Fin 4) :
    roundsFrom w (counterBlock nonce a) 1 (stateIndex c j) =
      roundsFrom w (counterBlock nonce b) 1 (stateIndex c j) := by
  rw [rounds_step w _ 0 (by norm_num), rounds_step w _ 0 (by norm_num)]
  simp only [fullRound, columnOf_stateIndex, rowOf_stateIndex]
  congr 3
  funext r
  congr 1
  apply state0_ne15 w nonce ha hb
  simp only [columnSource]
  omega

theorem counterBlock_hi (nonce : Fin 12 → Byte) {a : ℕ} (ha : a < 256) (j : ℕ) (hj : 12 ≤ j)
    (hj' : j < 15) : counterBlock nonce a ⟨j, by omega⟩ = 0 := by
  have hpow : 256 ≤ 256 ^ (3 - (j - 12)) :=
    calc 256 = 256 ^ 1 := by norm_num
      _ ≤ 256 ^ (3 - (j - 12)) := Nat.pow_le_pow_right (by norm_num) (by omega)
  simp only [counterBlock, show ¬ j < 12 by omega, dite_false, be32]
  rw [Nat.div_eq_of_lt (by omega)]
  rfl

theorem low32_counterBlock (nonce : Fin 12 → Byte) {a : ℕ} (ha : a < 256) :
    low32 (counterBlock nonce a) = a := by
  unfold low32
  rw [show (12 : Fin 16) = ⟨12, by norm_num⟩ from rfl, show (13 : Fin 16) = ⟨13, by norm_num⟩ from rfl,
    show (14 : Fin 16) = ⟨14, by norm_num⟩ from rfl, show (15 : Fin 16) = ⟨15, by norm_num⟩ from rfl,
    counterBlock_hi nonce ha 12 (by norm_num) (by norm_num),
    counterBlock_hi nonce ha 13 (by norm_num) (by norm_num),
    counterBlock_hi nonce ha 14 (by norm_num) (by norm_num), counterBlock_15 nonce ha]
  simp [Nat.mod_eq_of_lt ha]

theorem inc32_counterBlock (nonce : Fin 12 → Byte) {a : ℕ} (ha : a + 1 < 256) :
    inc32 (counterBlock nonce a) = counterBlock nonce (a + 1) := by
  funext i
  unfold inc32
  rw [low32_counterBlock nonce (by omega)]
  by_cases h12 : i.val < 12 <;> simp [h12, counterBlock]

theorem ctrEncrypt_40 (key : Fin 32 → Byte) (nonce : Fin 12 → Byte) (pt : Fin 40 → Byte) :
    ctrEncrypt key nonce (List.ofFn pt) =
      (List.ofFn fun i : Fin 16 => pt ⟨i.val, by omega⟩ ^^^ encryptBlock key (counterBlock nonce 2) i) ++
      (List.ofFn fun i : Fin 16 => pt ⟨16 + i.val, by omega⟩ ^^^ encryptBlock key (counterBlock nonce 3) i) ++
      (List.ofFn fun i : Fin 8 =>
        pt ⟨32 + i.val, by omega⟩ ^^^ encryptBlock key (counterBlock nonce 4) ⟨i.val, by omega⟩) := by
  simp only [ctrEncrypt, ctrGeneric, List.length_ofFn]
  show ctrBlocks _ _ 3 _ = _
  simp only [ctrBlocks, List.append_nil, inc32_counterBlock nonce (by norm_num : 2 + 1 < 256),
    inc32_counterBlock nonce (by norm_num : 3 + 1 < 256), List.append_assoc]
  refine congrArg₂ (· ++ ·) ?_ (congrArg₂ (· ++ ·) ?_ ?_)
  · apply List.ext_get
    · simp
    · intro n h1 h2
      simp
  · apply List.ext_get
    · simp
    · intro n h1 h2
      simp [Nat.add_comm]
  · apply List.ext_get
    · simp
    · intro n h1 h2
      simp [Nat.add_comm]

variable [Fact (Nat.Prime Order)]

theorem counterByte3_cps (hL : AesLookupSem) (key : Byte) {SK : F} (hsk : SK = (spread8 key : F))
    {k : F → Prop} (h : AesCounterByte_3 SK k) : k ((key ^^^ 3#8).toNat : F) := by
  unfold AesCounterByte_3 at h
  simp only [exists_eq_left, gate_add, gate_mul] at h
  have h := decodeWord1_cps hL (by norm_num) ![key, 3#8] ?_ h
  · simpa [xorAll_two] using h
  · rw [hsk]
    simp only [Fin.sum_univ_two]
    have : spread8 3#8 = 7 := by decide
    simp [this]

theorem counterByte4_cps (hL : AesLookupSem) (key : Byte) {SK : F} (hsk : SK = (spread8 key : F))
    {k : F → Prop} (h : AesCounterByte_4 SK k) : k ((key ^^^ 4#8).toNat : F) := by
  unfold AesCounterByte_4 at h
  simp only [exists_eq_left, gate_add, gate_mul] at h
  have h := decodeWord1_cps hL (by norm_num) ![key, 4#8] ?_ h
  · simpa [xorAll_two] using h
  · rw [hsk]
    simp only [Fin.sum_univ_two]
    have : spread8 4#8 = 36 := by decide
    simp [this]

theorem finalRound8_cps (hL : AesLookupSem) (st : Fin 16 → Byte) (rk pt : Fin 8 → Byte)
    {State : List.Vector F 16} {RK PT : List.Vector F 8} (hst : ∀ i, State.get i = ((st i).toNat : F))
    (hrk : ∀ i, RK.get i = (spread8 (rk i) : F)) (hpt : ∀ i, PT.get i = (spread8 (pt i) : F))
    {k : List.Vector F 8 → Prop} (h : AesFinalRound_16_8_8 State RK PT k) :
    k (List.Vector.ofFn fun i : Fin 8 =>
      ((sb (st (columnSource (columnOf ⟨i.val, by omega⟩) (rowOf ⟨i.val, by omega⟩))) ^^^ rk i ^^^
        pt i).toNat : F)) := by
  unfold AesFinalRound_16_8_8 at h
  simp only [exists_eq_left, gate_add, gate_mul] at h
  have h := sbox_step hL.subst (st 0) (hst 0) (by norm_num) h
  have h := sbox_step hL.subst (st 5) (hst 5) (by norm_num) h
  have h := sbox_step hL.subst (st 10) (hst 10) (by norm_num) h
  have h := sbox_step hL.subst (st 15) (hst 15) (by norm_num) h
  have h := sbox_step hL.subst (st 4) (hst 4) (by norm_num) h
  have h := sbox_step hL.subst (st 9) (hst 9) (by norm_num) h
  have h := sbox_step hL.subst (st 14) (hst 14) (by norm_num) h
  have h := sbox_step hL.subst (st 3) (hst 3) (by norm_num) h
  have h := decodeWord4_cps hL (by norm_num)
    (fun j => ![sb (st (columnSource 0 j)), rk ⟨j.val, by omega⟩, pt ⟨j.val, by omega⟩]) ?_ h
  · have h := decodeWord4_cps hL (by norm_num)
      (fun j => ![sb (st (columnSource 1 j)), rk ⟨4 + j.val, by omega⟩, pt ⟨4 + j.val, by omega⟩]) ?_ h
    · convert h using 1
      apply List.Vector.ext
      intro i
      fin_cases i <;> simp [xorAll_three] <;> rfl
    · rw [hrk 4, hrk 5, hrk 6, hrk 7, hpt 4, hpt 5, hpt 6, hpt 7]
      simp [Fin.sum_univ_four, Fin.sum_univ_three]
      rfl
  · rw [hrk 0, hrk 1, hrk 2, hrk 3, hpt 0, hpt 1, hpt 2, hpt 3]
    simp [Fin.sum_univ_four, Fin.sum_univ_three]
    rfl

/-- The column-0 partial sum of round 1 over regions 0 to 2: the spread
round-key word and the substitution words of state bytes 0, 5 and 10. The
envelope circuits compute it once and reuse it for every counter. -/
def cachedSum (a0 a5 a10 : Byte) (rk : Fin 4 → Byte) : F :=
  (spread8 (rk 0) : F) + (spread8 (rk 1) : F) * 1679616 + (spread8 (rk 2) : F) * 2821109907456 +
    (spread8 (rk 3) : F) * 4738381338321616896 +
    (spreadWord (fun j => mixByte 0 j (sb a0)) : F) + (spreadWord (fun j => mixByte 1 j (sb a5)) : F) +
    (spreadWord (fun j => mixByte 2 j (sb a10)) : F)

theorem cachedSum_cps (hL : AesLookupSem) (a0 a5 a10 : Byte) (rk : Fin 4 → Byte)
    {s0 s1 s2 x0 x1 x2 x3 : F}
    (hs0 : s0 = (a0.toNat : F)) (hs1 : s1 = (a5.toNat : F)) (hs2 : s2 = (a10.toNat : F))
    (hx0 : x0 = (spread8 (rk 0) : F)) (hx1 : x1 = (spread8 (rk 1) : F))
    (hx2 : x2 = (spread8 (rk 2) : F)) (hx3 : x3 = (spread8 (rk 3) : F))
    {k : F → Prop}
    (h : ∃ g71, g71 = Gates.mul x0 (1 : F) ∧ ∃ g72, g72 = Gates.add (0 : F) g71 ∧
      ∃ g73, g73 = Gates.mul x1 (1679616 : F) ∧ ∃ g74, g74 = Gates.add g72 g73 ∧
      ∃ g75, g75 = Gates.mul x2 (2821109907456 : F) ∧ ∃ g76, g76 = Gates.add g74 g75 ∧
      ∃ g77, g77 = Gates.mul x3 (4738381338321616896 : F) ∧ ∃ g78, g78 = Gates.add g76 g77 ∧
      ∃ g79, g79 = Gates.add s0 (0 : F) ∧ SubstitutionLookup g79 fun g80 =>
      ∃ g81, g81 = Gates.add g78 g80 ∧
      ∃ g82, g82 = Gates.add s1 (256 : F) ∧ SubstitutionLookup g82 fun g83 =>
      ∃ g84, g84 = Gates.add g81 g83 ∧
      ∃ g85, g85 = Gates.add s2 (512 : F) ∧ SubstitutionLookup g85 fun g86 =>
      ∃ g87, g87 = Gates.add g84 g86 ∧ k g87) :
    k (cachedSum a0 a5 a10 rk) := by
  simp only [exists_eq_left] at h
  have h := subst_step hL.subst 0 a0 hs0 (by rw [gate_add]; norm_num) h
  have h := subst_step hL.subst 1 a5 hs1 (by rw [gate_add]; norm_num) h
  have h := subst_step hL.subst 2 a10 hs2 (by rw [gate_add]; norm_num) h
  refine (congrArg k ?_).mpr h
  rw [hx0, hx1, hx2, hx3, cachedSum]
  simp only [gate_add, gate_mul]
  ring

/-- Column 0 of round 1 for one counter: the counter byte gadget `CB`, its
region-3 substitution, the cached partial sum, and the decode. -/
theorem colZero_cps (hL : AesLookupSem) (st rk T : State) (hT : T = fullRound st rk)
    (key15 c : Byte) (hst15 : st 15 = key15 ^^^ c) {CB : F → (F → Prop) → Prop} {SK SC : F}
    (hCB : ∀ k' : F → Prop, CB SK k' → k' ((key15 ^^^ c).toNat : F))
    (hSC : SC = cachedSum (st 0) (st 5) (st 10) (fun j => rk ⟨j.val, by omega⟩))
    {k : List.Vector F 4 → Prop}
    (h : CB SK fun g88 => ∃ g89, g89 = Gates.add g88 (768 : F) ∧ SubstitutionLookup g89 fun g90 =>
      ∃ g91, g91 = Gates.add SC g90 ∧ AesDecodeWord_4 g91 fun g92 => k g92) :
    k (colVec T 0) := by
  have h := hCB _ h
  simp only [exists_eq_left] at h
  rw [← hst15] at h
  have h := subst_step hL.subst 3 (st 15) rfl
    (by rw [gate_add, show ((3 : Fin 4) : ℕ) = 3 from rfl]; norm_num) h
  let b : Fin 4 → Fin 5 → Byte := fun j =>
    ![![rk 0, rk 1, rk 2, rk 3] j, mixByte 0 j (sb (st 0)), mixByte 1 j (sb (st 5)),
      mixByte 2 j (sb (st 10)), mixByte 3 j (sb (st 15))]
  have h := decodeWord4_cps hL (by norm_num) b ?_ h
  · convert h using 1
    unfold colVec
    congr 1
    funext j
    rw [hT]
    simp only [fullRound, columnOf_stateIndex, rowOf_stateIndex, mixColumn_eq_mixBytes]
    have e0 : st (columnSource 0 0) = st 0 := rfl
    have e1 : st (columnSource 0 1) = st 5 := rfl
    have e2 : st (columnSource 0 2) = st 10 := rfl
    have e3 : st (columnSource 0 3) = st 15 := rfl
    rw [e0, e1, e2, e3]
    congr 2
    have er : ![rk 0, rk 1, rk 2, rk 3] j = rk (stateIndex 0 j) := by fin_cases j <;> rfl
    simp only [b, xorAll_five, er]
    ac_rfl
  · have h3 : ((3 : Fin 4) : ℕ) = 3 := rfl
    rw [hSC, cachedSum]
    simp only [gate_add, spreadWord, Fin.sum_univ_four, Fin.sum_univ_five, b]
    simp [h3]
    ring

end ZolanaVE.Aes
