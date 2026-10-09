import VerifiableEncryption.Aes.Tables

namespace ZolanaVE.Aes

open Finset

/-! Hand mirrors of the gadget constraints in `aes/cipher.go` and
`aes/spread_bytes.go`. Lookups are relations whose semantics enter only as the
`*LookupSound` hypotheses; they are replaced by the extracted definitions once
Track S lands `Circuit.lean`. -/

variable {p : ℕ} [NeZero p]

def SpreadByteLookupSound (lookup : ZMod p → ZMod p → Prop) : Prop :=
  ∀ a out, lookup a out → a.val < 256 ∧ out = ((AesTables.spreadBytes.getD a.val 0 : ℕ) : ZMod p)

def SubstLookupSound (lookup : ZMod p → ZMod p → Prop) : Prop :=
  ∀ i out, lookup i out → i.val < 1280 ∧ out = ((substitutionAt i.val : ℕ) : ZMod p)

def packWord (v : Fin 4 → ZMod p) : ZMod p :=
  v 0 + v 1 * 6 ^ 8 + v 2 * 6 ^ 16 + v 3 * 6 ^ 24

omit [NeZero p] in
theorem val_natCast_of_lt {n : ℕ} (h : n < p) : ((n : ZMod p)).val = n := by
  rw [ZMod.val_natCast, Nat.mod_eq_of_lt h]

theorem spreadByte_of_lookup {lookup : ZMod p → ZMod p → Prop} (hL : SpreadByteLookupSound lookup)
    {a out : ZMod p} (h : lookup a out) :
    ∃ x : Byte, a = (x.toNat : ZMod p) ∧ out = (spread8 x : ZMod p) := by
  obtain ⟨ha, hout⟩ := hL a out h
  refine ⟨BitVec.ofNat 8 a.val, ?_, ?_⟩
  · rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt ha, ZMod.natCast_zmod_val]
  · rw [hout, bytesTable_spec _ ha, spread8, BitVec.toNat_ofNat, Nat.mod_eq_of_lt ha]

omit [NeZero p] in
theorem spreadByte_correct {lookup : ZMod p → ZMod p → Prop} (hp : 256 < p)
    (hL : SpreadByteLookupSound lookup) (x : Byte) {out : ZMod p}
    (h : lookup (x.toNat : ZMod p) out) : out = (spread8 x : ZMod p) := by
  obtain ⟨_, hout⟩ := hL _ out h
  rw [hout, val_natCast_of_lt (by have := x.isLt; omega), bytesTable_spread8]

omit [NeZero p] in
theorem subst_index_val (hp : 1280 < p) (x : Byte) (r : ℕ) (hr : r < 5) :
    ((x.toNat : ZMod p) + ((256 * r : ℕ) : ZMod p)).val = x.toNat + 256 * r := by
  have := x.isLt
  rw [← Nat.cast_add, val_natCast_of_lt (by omega)]

omit [NeZero p] in
theorem subst_mix {lookup : ZMod p → ZMod p → Prop} (hp : 1280 < p) (hL : SubstLookupSound lookup)
    (r : Fin 4) (x : Byte) {out : ZMod p}
    (h : lookup ((x.toNat : ZMod p) + ((256 * r.val : ℕ) : ZMod p)) out) :
    out = (spreadWord (fun j => mixByte r j (sb x)) : ZMod p) := by
  obtain ⟨_, hout⟩ := hL _ out h
  rw [hout, subst_index_val hp x r.val (by omega), substitution_mix_spec]

omit [NeZero p] in
theorem subst_sbox {lookup : ZMod p → ZMod p → Prop} (hp : 1280 < p) (hL : SubstLookupSound lookup)
    (x : Byte) {out : ZMod p} (h : lookup ((x.toNat : ZMod p) + ((256 * 4 : ℕ) : ZMod p)) out) :
    out = (spread8 (sb x) : ZMod p) := by
  obtain ⟨_, hout⟩ := hL _ out h
  rw [hout, subst_index_val hp x 4 (by omega), substitution_sbox_spec]

theorem decodeWord_xor {m k : ℕ} (hp : 6 ^ 32 < p) (hm : m ≤ 4) (hk : k ≤ 5)
    (b : Fin m → Fin k → Byte) {lookup : ZMod p → ZMod p → Prop}
    (hL : ChunkLookupSound lookup) {S : ZMod p} {chunks nibbles : Fin (2 * m) → ZMod p}
    {bytes : Fin m → ZMod p}
    (hS : S = ∑ j : Fin m, (∑ t, (spread8 (b j t) : ZMod p)) * ((6 : ZMod p) ^ 8) ^ j.val)
    (h : DecodeWord lookup m S chunks nibbles bytes) :
    ∀ j, bytes j = ((xorAll (b j)).toNat : ZMod p) := by
  refine decodeWord_sound hp hm hk b hL ?_ h
  rw [hS]
  norm_num

theorem xorAll_two (a b : Byte) : xorAll ![a, b] = a ^^^ b := by
  simp [xorAll]

theorem xorAll_three (a b c : Byte) : xorAll ![a, b, c] = a ^^^ b ^^^ c := by
  simp [xorAll, BitVec.xor_assoc]

theorem xorAll_five (a b c d e : Byte) : xorAll ![a, b, c, d, e] = a ^^^ b ^^^ c ^^^ d ^^^ e := by
  simp [xorAll, BitVec.xor_assoc]

theorem mixColumn_eq_mixBytes (c : Fin 4 → Byte) (j : Fin 4) :
    mixColumn c j = mixByte 0 j (c 0) ^^^ mixByte 1 j (c 1) ^^^ mixByte 2 j (c 2) ^^^ mixByte 3 j (c 3) := by
  fin_cases j <;> simp [mixColumn, mixByte] <;> ac_rfl

/-- One output column of a full round: the spread round-key word plus the four
MixColumns substitution words, decoded. `S` is the packed sum as built by
`columnSum`; the cached first-round column splits the same sum. -/
def AesRoundColumn (subst chunk : ZMod p → ZMod p → Prop) (S : ZMod p) (rkSpread src : Fin 4 → ZMod p)
    (out : Fin 4 → ZMod p) : Prop :=
  ∃ subOut : Fin 4 → ZMod p, ∃ chunks nibbles : Fin (2 * 4) → ZMod p,
    (∀ r : Fin 4, subst (src r + ((256 * r.val : ℕ) : ZMod p)) (subOut r)) ∧
    S = packWord rkSpread + subOut 0 + subOut 1 + subOut 2 + subOut 3 ∧
    DecodeWord chunk 4 S chunks nibbles out

theorem roundColumn_correct {subst chunk : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hsubst : SubstLookupSound subst) (hchunk : ChunkLookupSound chunk)
    (s rk : Fin 4 → Byte) {S : ZMod p} {rkSpread src out : Fin 4 → ZMod p}
    (hsrc : ∀ r, src r = ((s r).toNat : ZMod p)) (hrk : ∀ j, rkSpread j = (spread8 (rk j) : ZMod p))
    (h : AesRoundColumn subst chunk S rkSpread src out) :
    ∀ j, out j = ((mixColumn (fun r => sb (s r)) j ^^^ rk j).toNat : ZMod p) := by
  obtain ⟨subOut, chunks, nibbles, hsub, hsum, hdec⟩ := h
  have hp' : 1280 < p := lt_trans (by norm_num) hp
  have hsub' : ∀ r : Fin 4, subOut r = (spreadWord (fun j => mixByte r j (sb (s r))) : ZMod p) := by
    intro r
    have := hsub r
    rw [hsrc r] at this
    exact subst_mix hp' hsubst r (s r) this
  let b : Fin 4 → Fin 5 → Byte := fun j =>
    ![rk j, mixByte 0 j (sb (s 0)), mixByte 1 j (sb (s 1)), mixByte 2 j (sb (s 2)),
      mixByte 3 j (sb (s 3))]
  have hdecoded := decodeWord_xor hp (by norm_num) (by norm_num) b hchunk ?_ hdec
  · intro j
    rw [hdecoded j]
    congr 2
    simp only [b, xorAll_five, mixColumn_eq_mixBytes]
    ac_rfl
  · rw [hsum, packWord, hsub' 0, hsub' 1, hsub' 2, hsub' 3, hrk 0, hrk 1, hrk 2, hrk 3]
    have h3 : ((3 : Fin 4) : ℕ) = 3 := rfl
    simp only [spreadWord, Fin.sum_univ_four, Fin.sum_univ_five, b]
    simp [h3]
    ring

/-- Mirror of one 4-byte group of the final round: S-box region lookup, the
spread last round key, and the spread plaintext, decoded together. -/
def AesFinalRoundWord (subst chunk : ZMod p → ZMod p → Prop) {m : ℕ} (src rkSpread ptSpread : Fin m → ZMod p)
    (out : Fin m → ZMod p) : Prop :=
  ∃ subOut : Fin m → ZMod p, ∃ chunks nibbles : Fin (2 * m) → ZMod p,
    (∀ j, subst (src j + ((256 * 4 : ℕ) : ZMod p)) (subOut j)) ∧
    DecodeWord chunk m (∑ j : Fin m, (subOut j + rkSpread j + ptSpread j) * ((6 : ZMod p) ^ 8) ^ j.val)
      chunks nibbles out

theorem finalRound_correct {subst chunk : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hsubst : SubstLookupSound subst) (hchunk : ChunkLookupSound chunk) {m : ℕ} (hm : m ≤ 4)
    (s rk pt : Fin m → Byte) {src rkSpread ptSpread out : Fin m → ZMod p}
    (hsrc : ∀ j, src j = ((s j).toNat : ZMod p)) (hrk : ∀ j, rkSpread j = (spread8 (rk j) : ZMod p))
    (hpt : ∀ j, ptSpread j = (spread8 (pt j) : ZMod p))
    (h : AesFinalRoundWord subst chunk src rkSpread ptSpread out) :
    ∀ j, out j = ((sb (s j) ^^^ rk j ^^^ pt j).toNat : ZMod p) := by
  obtain ⟨subOut, chunks, nibbles, hsub, hdec⟩ := h
  have hp' : 1280 < p := lt_trans (by norm_num) hp
  have hsub' : ∀ j, subOut j = (spread8 (sb (s j)) : ZMod p) := by
    intro j
    have := hsub j
    rw [hsrc j] at this
    exact subst_sbox hp' hsubst (s j) this
  let b : Fin m → Fin 3 → Byte := fun j => ![sb (s j), rk j, pt j]
  have hdecoded := decodeWord_xor hp hm (by norm_num) b hchunk ?_ hdec
  · intro j
    rw [hdecoded j]
    simp only [b, xorAll_three]
  · refine Finset.sum_congr rfl (fun j _ => ?_)
    rw [hsub' j, hrk j, hpt j]
    simp [Fin.sum_univ_three, b]

/-- Mirror of `addRoundKey` and of a non-zero `counterByte`: a group of up to
four spread byte pairs decoded to their XOR. -/
def AesXorWord (chunk : ZMod p → ZMod p → Prop) {m : ℕ} (lhs rhs : Fin m → ZMod p)
    (out : Fin m → ZMod p) : Prop :=
  ∃ chunks nibbles : Fin (2 * m) → ZMod p,
    DecodeWord chunk m (∑ j : Fin m, (lhs j + rhs j) * ((6 : ZMod p) ^ 8) ^ j.val) chunks nibbles out

theorem xorWord_correct {chunk : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hchunk : ChunkLookupSound chunk) {m : ℕ} (hm : m ≤ 4) (x y : Fin m → Byte)
    {lhs rhs out : Fin m → ZMod p}
    (hx : ∀ j, lhs j = (spread8 (x j) : ZMod p)) (hy : ∀ j, rhs j = (spread8 (y j) : ZMod p))
    (h : AesXorWord chunk lhs rhs out) :
    ∀ j, out j = ((x j ^^^ y j).toNat : ZMod p) := by
  obtain ⟨chunks, nibbles, hdec⟩ := h
  let b : Fin m → Fin 2 → Byte := fun j => ![x j, y j]
  have hdecoded := decodeWord_xor hp hm (by norm_num) b hchunk ?_ hdec
  · intro j
    rw [hdecoded j]
    simp only [b, xorAll_two]
  · refine Finset.sum_congr rfl (fun j _ => ?_)
    rw [hx j, hy j]
    simp [Fin.sum_univ_two, b]

theorem counterByte_correct {chunk : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hchunk : ChunkLookupSound chunk) (key value : Byte) {keySpread out : ZMod p}
    (hkey : keySpread = (spread8 key : ZMod p))
    (h : AesXorWord (m := 1) chunk ![keySpread] ![(spread8 value : ZMod p)] ![out]) :
    out = ((key ^^^ value).toNat : ZMod p) := by
  have := xorWord_correct hp hchunk (by norm_num) ![key] ![value] (by simp [hkey]) (by simp) h 0
  simpa using this

theorem xorWord3_correct {chunk : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hchunk : ChunkLookupSound chunk) {m : ℕ} (hm : m ≤ 4) (x y z : Fin m → Byte)
    {lhs rhs out : Fin m → ZMod p}
    (hx : ∀ j, lhs j = (spread8 (x j) : ZMod p))
    (hyz : ∀ j, rhs j = (spread8 (y j) : ZMod p) + (spread8 (z j) : ZMod p))
    (h : AesXorWord chunk lhs rhs out) :
    ∀ j, out j = ((x j ^^^ y j ^^^ z j).toNat : ZMod p) := by
  obtain ⟨chunks, nibbles, hdec⟩ := h
  let b : Fin m → Fin 3 → Byte := fun j => ![x j, y j, z j]
  have hdecoded := decodeWord_xor hp hm (by norm_num) b hchunk ?_ hdec
  · intro j
    rw [hdecoded j]
    simp only [b, xorAll_three]
  · refine Finset.sum_congr rfl (fun j _ => ?_)
    rw [hx j, hyz j]
    simp [Fin.sum_univ_three, b, add_assoc]

/-- Key-expansion word kinds by `i % 32`: rotated S-box word plus round
constant at 0, S-box word at 16, previous word otherwise. -/
inductive KeyWordKind
  | rotSubRcon (rcon : Byte)
  | sub
  | copy

def keyWordSub (kind : KeyWordKind) (prev : Fin 4 → Byte) : Fin 4 → Byte :=
  match kind with
  | .rotSubRcon _ => fun j => sb (prev (j + 1))
  | .sub => fun j => sb (prev j)
  | .copy => prev

def keyWordConst (kind : KeyWordKind) : Fin 4 → Byte :=
  match kind with
  | .rotSubRcon rcon => fun j => if j = 0 then rcon else 0
  | .sub => fun _ => 0
  | .copy => fun _ => 0

def keyWordMixed (kind : KeyWordKind) (prev : Fin 4 → Byte) : Fin 4 → Byte :=
  fun j => keyWordSub kind prev j ^^^ keyWordConst kind j

/-- Mirror of one iteration of `expandRoundKeys`: the mixed operand, the
decoded XOR with the word eight positions back, and the spread lookups of the
new bytes. -/
def AesKeyWord (subst chunk spreadLookup : ZMod p → ZMod p → Prop) (kind : KeyWordKind)
    (prevBytes prevSpread earlierSpread : Fin 4 → ZMod p) (cur curSpread : Fin 4 → ZMod p) : Prop :=
  ∃ mixed : Fin 4 → ZMod p,
    (match kind with
      | .rotSubRcon rcon => ∃ subOut : Fin 4 → ZMod p,
          (∀ j, subst (prevBytes (j + 1) + ((256 * 4 : ℕ) : ZMod p)) (subOut j)) ∧
          ∀ j, mixed j = subOut j + (if j = 0 then (spread8 rcon : ZMod p) else 0)
      | .sub => ∀ j, subst (prevBytes j + ((256 * 4 : ℕ) : ZMod p)) (mixed j)
      | .copy => mixed = prevSpread) ∧
    AesXorWord chunk earlierSpread mixed cur ∧
    ∀ j, spreadLookup (cur j) (curSpread j)

theorem spread8_zero : spread8 0#8 = 0 := by decide

theorem keyWord_correct {subst chunk spreadLookup : ZMod p → ZMod p → Prop} (hp : 6 ^ 32 < p)
    (hsubst : SubstLookupSound subst) (hchunk : ChunkLookupSound chunk)
    (hspread : SpreadByteLookupSound spreadLookup) (kind : KeyWordKind)
    (prev earlier : Fin 4 → Byte) {prevBytes prevSpread earlierSpread cur curSpread : Fin 4 → ZMod p}
    (hprev : ∀ j, prevBytes j = ((prev j).toNat : ZMod p))
    (hprevSpread : ∀ j, prevSpread j = (spread8 (prev j) : ZMod p))
    (hearlier : ∀ j, earlierSpread j = (spread8 (earlier j) : ZMod p))
    (h : AesKeyWord subst chunk spreadLookup kind prevBytes prevSpread earlierSpread cur curSpread) :
    ∀ j, cur j = ((earlier j ^^^ keyWordMixed kind prev j).toNat : ZMod p) ∧
      curSpread j = (spread8 (earlier j ^^^ keyWordMixed kind prev j) : ZMod p) := by
  obtain ⟨mixed, hmixed, hxor, hlk⟩ := h
  have hp' : 1280 < p := lt_trans (by norm_num) hp
  have hmixed' : ∀ j, mixed j = (spread8 (keyWordSub kind prev j) : ZMod p) +
      (spread8 (keyWordConst kind j) : ZMod p) := by
    cases kind with
    | rotSubRcon rcon =>
      obtain ⟨subOut, hsub, hm⟩ := hmixed
      intro j
      have hs := hsub j
      rw [hprev] at hs
      rw [hm j, subst_sbox hp' hsubst _ hs, keyWordSub, keyWordConst]
      by_cases hj : j = 0 <;> simp [hj, spread8_zero]
    | sub =>
      intro j
      have hs := hmixed j
      rw [hprev] at hs
      rw [subst_sbox hp' hsubst _ hs, keyWordSub, keyWordConst]
      simp [spread8_zero]
    | copy =>
      intro j
      rw [hmixed, hprevSpread, keyWordSub, keyWordConst]
      simp [spread8_zero]
  have hcur := xorWord3_correct hp hchunk (by norm_num) earlier (keyWordSub kind prev)
    (keyWordConst kind) hearlier hmixed' hxor
  have hcur' : ∀ j, cur j = ((earlier j ^^^ keyWordMixed kind prev j).toNat : ZMod p) := by
    intro j
    rw [hcur j, keyWordMixed, BitVec.xor_assoc]
  intro j
  refine ⟨hcur' j, ?_⟩
  have := hlk j
  rw [hcur' j] at this
  exact spreadByte_correct (lt_trans (by norm_num) hp) hspread _ this

end ZolanaVE.Aes
