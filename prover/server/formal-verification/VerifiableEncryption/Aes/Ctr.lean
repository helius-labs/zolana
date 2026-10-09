import VerifiableEncryption.Aes.Round

namespace ZolanaVE.Aes

/-! Block-level composition of the gadget mirrors. States are column-major
`Fin 16` byte vectors, as in `cipher.go`. -/

/-- State byte feeding row `r` of output column `c` after ShiftRows; equals the
`columnSources` table and `byteOrder` in `cipher.go`. -/
def columnSource (c r : Fin 4) : Fin 16 :=
  ⟨4 * ((c.val + r.val) % 4) + r.val, by omega⟩

def stateIndex (c j : Fin 4) : Fin 16 := ⟨4 * c.val + j.val, by omega⟩

def columnOf (i : Fin 16) : Fin 4 := ⟨i.val / 4, by omega⟩

def rowOf (i : Fin 16) : Fin 4 := ⟨i.val % 4, by omega⟩

theorem stateIndex_columnOf_rowOf (i : Fin 16) : stateIndex (columnOf i) (rowOf i) = i :=
  Fin.ext (by simp [stateIndex, columnOf, rowOf]; omega)

theorem columnSource_table :
    (List.finRange 16).map (fun i => (columnSource (columnOf i) (rowOf i)).val) =
      [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11] := by
  decide

/-- SubBytes, ShiftRows, MixColumns and AddRoundKey as the circuit computes
them column by column. -/
def fullRound (st rk : Fin 16 → Byte) : Fin 16 → Byte :=
  fun i => mixColumn (fun r => sb (st (columnSource (columnOf i) r))) (rowOf i) ^^^ rk i

def finalRoundBytes (st rk : Fin 16 → Byte) : Fin 16 → Byte :=
  fun i => sb (st (columnSource (columnOf i) (rowOf i))) ^^^ rk i

def addRoundKey (st rk : Fin 16 → Byte) : Fin 16 → Byte := fun i => st i ^^^ rk i

/-- Rounds `1..n` applied to the state after the initial AddRoundKey. -/
def applyRounds (rk : Fin 15 → Fin 16 → Byte) : ℕ → (Fin 16 → Byte) → Fin 16 → Byte
  | 0, st => st
  | n + 1, st => fullRound (applyRounds rk n st) (rk ⟨(n + 1) % 15, Nat.mod_lt _ (by norm_num)⟩)

def circuitEncryptBlock (rk : Fin 15 → Fin 16 → Byte) (blk : Fin 16 → Byte) : Fin 16 → Byte :=
  finalRoundBytes (applyRounds rk 13 (addRoundKey blk (rk 0))) (rk 14)

variable {p : ℕ} [NeZero p]

def AesRoundState (subst chunk : ZMod p → ZMod p → Prop) (rkSpread st next : Fin 16 → ZMod p) : Prop :=
  ∀ c : Fin 4, ∃ S : ZMod p, AesRoundColumn subst chunk S (fun j => rkSpread (stateIndex c j))
    (fun r => st (columnSource c r)) (fun j => next (stateIndex c j))

theorem roundState_correct {subst chunk : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hsubst : SubstLookupSound subst) (hchunk : ChunkLookupSound chunk)
    (st rk : Fin 16 → Byte) {rkSpread stF next : Fin 16 → ZMod p}
    (hst : ∀ i, stF i = ((st i).toNat : ZMod p)) (hrk : ∀ i, rkSpread i = (spread8 (rk i) : ZMod p))
    (h : AesRoundState subst chunk rkSpread stF next) :
    ∀ i, next i = ((fullRound st rk i).toNat : ZMod p) := by
  intro i
  obtain ⟨S, hcol⟩ := h (columnOf i)
  have := roundColumn_correct hp hsubst hchunk (fun r => st (columnSource (columnOf i) r))
    (fun j => rk (stateIndex (columnOf i) j)) (fun r => hst _) (fun j => hrk _) hcol (rowOf i)
  rw [stateIndex_columnOf_rowOf] at this
  rw [this, fullRound]

omit [NeZero p] in
/-- The cached first-round column 0 of `ctrStream.encryptBlock`: regions 0..2
summed once per counter high part, region 3 added per low counter byte. The
split sum equals the uncached `columnSum`, so `AesRoundColumn` applies. -/
theorem cachedColumn_sum (rkSpread subOut : Fin 4 → ZMod p) {columnZero S : ZMod p}
    (hzero : columnZero = packWord rkSpread + subOut 0 + subOut 1 + subOut 2)
    (hS : S = columnZero + subOut 3) :
    S = packWord rkSpread + subOut 0 + subOut 1 + subOut 2 + subOut 3 := by
  rw [hS, hzero]

theorem counterByte_zero (key : Byte) : key ^^^ 0#8 = key := BitVec.xor_zero

theorem rounds_correct {subst chunk : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hsubst : SubstLookupSound subst) (hchunk : ChunkLookupSound chunk)
    (rk : Fin 15 → Fin 16 → Byte) (rkSpread : Fin 15 → Fin 16 → ZMod p)
    (hrk : ∀ r i, rkSpread r i = (spread8 (rk r i) : ZMod p))
    (st0 : Fin 16 → Byte) (states : ℕ → Fin 16 → ZMod p)
    (h0 : ∀ i, states 0 i = ((st0 i).toNat : ZMod p))
    (hround : ∀ n, n < 13 → AesRoundState subst chunk
      (rkSpread ⟨(n + 1) % 15, Nat.mod_lt _ (by norm_num)⟩) (states n) (states (n + 1))) :
    ∀ n, n ≤ 13 → ∀ i, states n i = ((applyRounds rk n st0 i).toNat : ZMod p)
  | 0, _ => h0
  | n + 1, hn => by
    have ih := rounds_correct hp hsubst hchunk rk rkSpread hrk st0 states h0 hround n (by omega)
    exact roundState_correct hp hsubst hchunk _ _ ih (fun i => hrk _ i) (hround n (by omega))

theorem AesCtrBlock_sound {subst chunk : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hsubst : SubstLookupSound subst) (hchunk : ChunkLookupSound chunk)
    (rk : Fin 15 → Fin 16 → Byte) (rkSpread : Fin 15 → Fin 16 → ZMod p)
    (hrk : ∀ r i, rkSpread r i = (spread8 (rk r i) : ZMod p))
    (blk pt : Fin 16 → Byte) (states : ℕ → Fin 16 → ZMod p) (ptSpread out : Fin 16 → ZMod p)
    (hinit : ∀ i, states 0 i = ((blk i ^^^ rk 0 i).toNat : ZMod p))
    (hround : ∀ n, n < 13 → AesRoundState subst chunk
      (rkSpread ⟨(n + 1) % 15, Nat.mod_lt _ (by norm_num)⟩) (states n) (states (n + 1)))
    (hpt : ∀ i, ptSpread i = (spread8 (pt i) : ZMod p))
    (hfinal : ∀ c : Fin 4, AesFinalRoundWord (m := 4) subst chunk
      (fun j => states 13 (columnSource c j)) (fun j => rkSpread 14 (stateIndex c j))
      (fun j => ptSpread (stateIndex c j)) (fun j => out (stateIndex c j))) :
    ∀ i, out i = ((circuitEncryptBlock rk blk i ^^^ pt i).toNat : ZMod p) := by
  have hstates := rounds_correct hp hsubst hchunk rk rkSpread hrk (addRoundKey blk (rk 0)) states
    hinit hround 13 le_rfl
  intro i
  have := finalRound_correct hp hsubst hchunk le_rfl
    (fun j => applyRounds rk 13 (addRoundKey blk (rk 0)) (columnSource (columnOf i) j))
    (fun j => rk 14 (stateIndex (columnOf i) j)) (fun j => pt (stateIndex (columnOf i) j))
    (fun j => hstates _) (fun j => hrk _ _) (fun j => hpt _) (hfinal (columnOf i)) (rowOf i)
  rw [stateIndex_columnOf_rowOf] at this
  rw [this, circuitEncryptBlock, finalRoundBytes]

end ZolanaVE.Aes
