import VerifiableEncryption.Aes.KeySteps

/-!
State-level continuation lemmas for the extracted `AesCtrBlock_32_12_16_16`,
and the bridge from the circuit's column-wise round to `cipherRound`.
-/

namespace ZolanaVE.Aes

open ZolanaVE

theorem columnOf_stateIndex (c j : Fin 4) : columnOf (stateIndex c j) = c :=
  Fin.ext (by simp [columnOf, stateIndex] <;> omega)

theorem rowOf_stateIndex (c j : Fin 4) : rowOf (stateIndex c j) = j :=
  Fin.ext (by simp [rowOf, stateIndex] <;> omega)

theorem columnSource_eq_idx (c r : Fin 4) : columnSource c r = idx r (c + r) :=
  Fin.ext (by simp [columnSource, idx, Fin.val_add]; omega)

theorem fullRound_eq_cipherRound (w : Fin 60 → Word) (r : Fin 15) (s : State) :
    fullRound s (roundKey w r) = cipherRound w r s := by
  funext i
  simp only [fullRound, cipherRound, addRoundKey, mixColumns]
  congr 2
  funext r'
  rw [column_shiftRows, columnSource_eq_idx]
  rfl

theorem finalRound_eq (w : Fin 60 → Word) (s : State) :
    finalRound w s = addRoundKey (fun i => sb (s (columnSource (columnOf i) (rowOf i)))) (roundKey w 14) := by
  funext i
  simp only [finalRound, addRoundKey, shiftRows, subBytes]
  rw [columnSource_eq_idx]
  rfl

theorem roundsFrom_succ (w : Fin 60 → Word) (blk : Block) (n : ℕ) (hn : n < 13) :
    roundsFrom w blk (n + 1) = fullRound (roundsFrom w blk n) (roundKey w ⟨n + 1, by omega⟩) := by
  have hr : (⟨min (n + 1) 14, by omega⟩ : Fin 15) = ⟨n + 1, by omega⟩ := Fin.ext (by simp; omega)
  rw [roundsFrom, fullRound_eq_cipherRound, hr]

variable [Fact (Nat.Prime Order)]

def colVec (S : State) (c : Fin 4) : List.Vector F 4 :=
  List.Vector.ofFn fun j => ((S (stateIndex c j)).toNat : F)

theorem roundColumnState_cps (hL : AesLookupSem) (st rk T : State) (hT : T = fullRound st rk)
    (c : Fin 4) {State R : List.Vector F 4}
    (hst : ∀ r, State.get r = ((st (columnSource c r)).toNat : F))
    (hR : ∀ j, R.get j = (spread8 (rk (stateIndex c j)) : F))
    {k : List.Vector F 4 → Prop} (h : AesRoundColumn_4_4 State R k) : k (colVec T c) := by
  have h := roundColumn_cps hL (fun r => st (columnSource c r)) (fun j => rk (stateIndex c j)) hst hR h
  convert h using 1
  unfold colVec
  congr 1
  funext j
  rw [hT]
  simp only [fullRound, columnOf_stateIndex, rowOf_stateIndex]

theorem roundColumnLit_cps (hL : AesLookupSem) (st rk T : State) (hT : T = fullRound st rk)
    (c : Fin 4) {e0 e1 e2 e3 x0 x1 x2 x3 : F}
    (he0 : e0 = ((st (columnSource c 0)).toNat : F)) (he1 : e1 = ((st (columnSource c 1)).toNat : F))
    (he2 : e2 = ((st (columnSource c 2)).toNat : F)) (he3 : e3 = ((st (columnSource c 3)).toNat : F))
    (hx0 : x0 = (spread8 (rk (stateIndex c 0)) : F)) (hx1 : x1 = (spread8 (rk (stateIndex c 1)) : F))
    (hx2 : x2 = (spread8 (rk (stateIndex c 2)) : F)) (hx3 : x3 = (spread8 (rk (stateIndex c 3)) : F))
    {k : List.Vector F 4 → Prop} (h : AesRoundColumn_4_4 vec![e0, e1, e2, e3] vec![x0, x1, x2, x3] k) :
    k (colVec T c) :=
  roundColumnState_cps hL st rk T hT c
    (by intro r; fin_cases r <;> assumption) (by intro j; fin_cases j <;> assumption) h

theorem round4_cps (hL : AesLookupSem) (st rk T : State) (hT : T = fullRound st rk)
    {x00 x01 x02 x03 x10 x11 x12 x13 x20 x21 x22 x23 x30 x31 x32 x33 : F}
    (hx00 : x00 = (spread8 (rk 0) : F))
    (hx01 : x01 = (spread8 (rk 1) : F))
    (hx02 : x02 = (spread8 (rk 2) : F))
    (hx03 : x03 = (spread8 (rk 3) : F))
    (hx10 : x10 = (spread8 (rk 4) : F))
    (hx11 : x11 = (spread8 (rk 5) : F))
    (hx12 : x12 = (spread8 (rk 6) : F))
    (hx13 : x13 = (spread8 (rk 7) : F))
    (hx20 : x20 = (spread8 (rk 8) : F))
    (hx21 : x21 = (spread8 (rk 9) : F))
    (hx22 : x22 = (spread8 (rk 10) : F))
    (hx23 : x23 = (spread8 (rk 11) : F))
    (hx30 : x30 = (spread8 (rk 12) : F))
    (hx31 : x31 = (spread8 (rk 13) : F))
    (hx32 : x32 = (spread8 (rk 14) : F))
    (hx33 : x33 = (spread8 (rk 15) : F))
    {k : List.Vector F 4 → List.Vector F 4 → List.Vector F 4 → List.Vector F 4 → Prop}
    (h : AesRoundColumn_4_4
        vec![(colVec st 0).get 0, (colVec st 1).get 1, (colVec st 2).get 2, (colVec st 3).get 3] vec![x00, x01, x02, x03]
        fun b0 => AesRoundColumn_4_4
        vec![(colVec st 1).get 0, (colVec st 2).get 1, (colVec st 3).get 2, (colVec st 0).get 3] vec![x10, x11, x12, x13]
        fun b1 => AesRoundColumn_4_4
        vec![(colVec st 2).get 0, (colVec st 3).get 1, (colVec st 0).get 2, (colVec st 1).get 3] vec![x20, x21, x22, x23]
        fun b2 => AesRoundColumn_4_4
        vec![(colVec st 3).get 0, (colVec st 0).get 1, (colVec st 1).get 2, (colVec st 2).get 3] vec![x30, x31, x32, x33]
        fun b3 => k b0 b1 b2 b3) :
    k (colVec T 0) (colVec T 1) (colVec T 2) (colVec T 3) := by
  have h := roundColumnState_cps hL st rk T hT 0 (by intro r; fin_cases r <;> rfl)
    (by intro j; fin_cases j <;> assumption) h
  have h := roundColumnState_cps hL st rk T hT 1 (by intro r; fin_cases r <;> rfl)
    (by intro j; fin_cases j <;> assumption) h
  have h := roundColumnState_cps hL st rk T hT 2 (by intro r; fin_cases r <;> rfl)
    (by intro j; fin_cases j <;> assumption) h
  exact roundColumnState_cps hL st rk T hT 3 (by intro r; fin_cases r <;> rfl)
    (by intro j; fin_cases j <;> assumption) h

/-- Column 0 of the first round, which `ctrStream.encryptBlock` splits into a
sum over regions 0..2 and the region-3 term of the counter byte. -/
theorem cachedColumn_cps (hL : AesLookupSem) (st rk T : State) (hT : T = fullRound st rk)
    (key15 : Byte) (hst15 : st 15 = key15 ^^^ 2#8) {s0 s1 s2 SK x0 x1 x2 x3 : F}
    (hs0 : s0 = ((st 0).toNat : F)) (hs1 : s1 = ((st 5).toNat : F)) (hs2 : s2 = ((st 10).toNat : F))
    (hSK : SK = (spread8 key15 : F))
    (hx0 : x0 = (spread8 (rk 0) : F)) (hx1 : x1 = (spread8 (rk 1) : F))
    (hx2 : x2 = (spread8 (rk 2) : F)) (hx3 : x3 = (spread8 (rk 3) : F))
    {k : List.Vector F 4 → Prop}
    (h : ∃ g71, g71 = Gates.mul x0 (1 : F) ∧ ∃ g72, g72 = Gates.add (0 : F) g71 ∧
      ∃ g73, g73 = Gates.mul x1 (1679616 : F) ∧ ∃ g74, g74 = Gates.add g72 g73 ∧
      ∃ g75, g75 = Gates.mul x2 (2821109907456 : F) ∧ ∃ g76, g76 = Gates.add g74 g75 ∧
      ∃ g77, g77 = Gates.mul x3 (4738381338321616896 : F) ∧ ∃ g78, g78 = Gates.add g76 g77 ∧
      ∃ g79, g79 = Gates.add s0 (0 : F) ∧ SubstitutionLookup g79 fun g80 =>
      ∃ g81, g81 = Gates.add g78 g80 ∧
      ∃ g82, g82 = Gates.add s1 (256 : F) ∧ SubstitutionLookup g82 fun g83 =>
      ∃ g84, g84 = Gates.add g81 g83 ∧
      ∃ g85, g85 = Gates.add s2 (512 : F) ∧ SubstitutionLookup g85 fun g86 =>
      ∃ g87, g87 = Gates.add g84 g86 ∧
      AesCounterByte_2 SK fun g88 =>
      ∃ g89, g89 = Gates.add g88 (768 : F) ∧ SubstitutionLookup g89 fun g90 =>
      ∃ g91, g91 = Gates.add g87 g90 ∧
      AesDecodeWord_4 g91 fun g92 => k g92) :
    k (colVec T 0) := by
  simp only [exists_eq_left] at h
  have h := subst_step hL.subst 0 (st 0) hs0 (by rw [gate_add]; norm_num) h
  have h := subst_step hL.subst 1 (st 5) hs1 (by rw [gate_add]; norm_num) h
  have h := subst_step hL.subst 2 (st 10) hs2 (by rw [gate_add]; norm_num) h
  have h := counterByte_cps hL key15 hSK h
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
    rw [hx0, hx1, hx2, hx3]
    simp only [gate_add, gate_mul, spreadWord, Fin.sum_univ_four, Fin.sum_univ_five, b]
    simp [h3]
    ring

theorem packDecode_cps (hL : AesLookupSem) {kk : ℕ} (hk : kk ≤ 5) (b : Fin 4 → Fin kk → Byte)
    {z0 z1 z2 z3 : F}
    (hz0 : z0 = ∑ t, (spread8 (b 0 t) : F)) (hz1 : z1 = ∑ t, (spread8 (b 1 t) : F))
    (hz2 : z2 = ∑ t, (spread8 (b 2 t) : F)) (hz3 : z3 = ∑ t, (spread8 (b 3 t) : F))
    {k : List.Vector F 4 → Prop}
    (h : ∃ g0, g0 = Gates.mul z0 (1 : F) ∧ ∃ g1, g1 = Gates.add (0 : F) g0 ∧
      ∃ g2, g2 = Gates.mul z1 (1679616 : F) ∧ ∃ g3, g3 = Gates.add g1 g2 ∧
      ∃ g4, g4 = Gates.mul z2 (2821109907456 : F) ∧ ∃ g5, g5 = Gates.add g3 g4 ∧
      ∃ g6, g6 = Gates.mul z3 (4738381338321616896 : F) ∧ ∃ g7, g7 = Gates.add g5 g6 ∧
      AesDecodeWord_4 g7 k) :
    k (List.Vector.ofFn fun j => ((xorAll (b j)).toNat : F)) := by
  simp only [exists_eq_left, gate_add, gate_mul] at h
  refine decodeWord4_cps hL hk b ?_ h
  have h3 : ((3 : Fin 4) : ℕ) = 3 := rfl
  rw [hz0, hz1, hz2, hz3]
  simp [Fin.sum_univ_four, h3]
  ring

end ZolanaVE.Aes
