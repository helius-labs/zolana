import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Data.ZMod.Basic
import VerifiableEncryption.AesTables

namespace ZolanaVE.Aes

open Finset

/-! Spread encoding: bit `i` of a byte becomes base-6 digit `i`, so a sum of at
most five spread bytes has no carries and each digit's parity is the XOR of the
summed bits. -/

def spreadBits : ℕ → ℕ → ℕ
  | 0, _ => 0
  | n + 1, v => v % 2 + 6 * spreadBits n (v / 2)

def spread8 (b : BitVec 8) : ℕ := spreadBits 8 b.toNat

def spreadWord (w : Fin 4 → BitVec 8) : ℕ :=
  spread8 (w 0) + 6 ^ 8 * spread8 (w 1) + 6 ^ 16 * spread8 (w 2) + 6 ^ 24 * spread8 (w 3)

def parityBits : ℕ → ℕ → ℕ
  | 0, _ => 0
  | n + 1, x => x % 6 % 2 + 2 * parityBits n (x / 6)

def chunkParity (c : ℕ) : ℕ := parityBits 4 c

def xorAll {w : ℕ} : {k : ℕ} → (Fin k → BitVec w) → BitVec w
  | 0, _ => 0
  | _ + 1, bs => bs 0 ^^^ xorAll (fun t => bs t.succ)

theorem digit_of_digits {b : ℕ} : ∀ {n : ℕ} (d : Fin n → ℕ), (∀ j, d j < b) → ∀ i : Fin n,
    (∑ j, d j * b ^ j.val) / b ^ i.val % b = d i
  | 0, _, _, i => i.elim0
  | n + 1, d, hd, i => by
    have hb : 0 < b := Nat.lt_of_le_of_lt (Nat.zero_le _) (hd 0)
    have hsplit : ∑ j : Fin (n + 1), d j * b ^ j.val
        = d 0 + b * ∑ j : Fin n, d j.succ * b ^ j.val := by
      rw [Fin.sum_univ_succ, Finset.mul_sum]
      simp only [Fin.val_zero, pow_zero, mul_one, Fin.val_succ, pow_succ]
      congr 1
      refine Finset.sum_congr rfl (fun j _ => ?_)
      ring
    rw [hsplit]
    refine Fin.cases ?_ (fun i => ?_) i
    · simp only [Fin.val_zero, pow_zero, Nat.div_one, Nat.add_mul_mod_self_left]
      exact Nat.mod_eq_of_lt (hd 0)
    · rw [Fin.val_succ, pow_succ', ← Nat.div_div_eq_div_mul]
      have : (d 0 + b * ∑ j : Fin n, d j.succ * b ^ j.val) / b
          = ∑ j : Fin n, d j.succ * b ^ j.val := by
        rw [Nat.add_mul_div_left _ _ hb, Nat.div_eq_of_lt (hd 0), zero_add]
      rw [this]
      exact digit_of_digits (fun j => d j.succ) (fun j => hd j.succ) i

theorem digits_lt {b : ℕ} : ∀ {n : ℕ} (d : Fin n → ℕ), (∀ j, d j < b) →
    ∑ j, d j * b ^ j.val < b ^ n
  | 0, _, _ => by simp
  | n + 1, d, hd => by
    rw [Fin.sum_univ_succ]
    have ih := digits_lt (fun j => d j.succ) (fun j => hd j.succ)
    have h0 := hd 0
    have : ∑ j : Fin n, d j.succ * b ^ (j.succ).val = b * ∑ j : Fin n, d j.succ * b ^ j.val := by
      rw [Finset.mul_sum]
      refine Finset.sum_congr rfl (fun j _ => ?_)
      rw [Fin.val_succ, pow_succ]
      ring
    simp only [Fin.val_zero, pow_zero, mul_one]
    rw [this, pow_succ']
    nlinarith

theorem spreadBits_eq_sum : ∀ (n v : ℕ),
    spreadBits n v = ∑ i : Fin n, (v.testBit i.val).toNat * 6 ^ i.val
  | 0, _ => by simp [spreadBits]
  | n + 1, v => by
    rw [spreadBits, spreadBits_eq_sum n (v / 2), Fin.sum_univ_succ, Finset.mul_sum]
    simp only [Fin.val_zero, pow_zero, mul_one, Fin.val_succ, Nat.testBit_succ]
    congr 1
    · rw [Nat.testBit_zero]
      rcases Nat.mod_two_eq_zero_or_one v with h | h <;> simp [h]
    · refine Finset.sum_congr rfl (fun i _ => ?_)
      rw [pow_succ]
      ring

theorem spread8_eq_sum (b : BitVec 8) :
    spread8 b = ∑ i : Fin 8, (b.getLsbD i.val).toNat * 6 ^ i.val :=
  spreadBits_eq_sum 8 b.toNat

theorem bool_toNat_lt_six (x : Bool) : x.toNat < 6 := by cases x <;> decide

theorem spread8_lt (b : BitVec 8) : spread8 b < 6 ^ 8 := by
  rw [spread8_eq_sum]
  exact digits_lt _ (fun _ => bool_toNat_lt_six _)

theorem spread8_digit (b : BitVec 8) (i : Fin 8) :
    spread8 b / 6 ^ i.val % 6 = (b.getLsbD i.val).toNat := by
  rw [spread8_eq_sum]
  exact digit_of_digits (fun j : Fin 8 => (b.getLsbD j.val).toNat) (fun _ => bool_toNat_lt_six _) i

theorem spread8_inj {a b : BitVec 8} (h : spread8 a = spread8 b) : a = b := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  have ha := spread8_digit a ⟨i, hi⟩
  have hb := spread8_digit b ⟨i, hi⟩
  rw [h, hb] at ha
  revert ha
  cases a.getLsbD i <;> cases b.getLsbD i <;> decide

theorem bit_sum_le {k : ℕ} (hk : k ≤ 5) (bs : Fin k → BitVec 8) (i : ℕ) :
    ∑ t, ((bs t).getLsbD i).toNat ≤ 5 := by
  calc ∑ t, ((bs t).getLsbD i).toNat ≤ ∑ _t : Fin k, 1 :=
        Finset.sum_le_sum (fun t _ => Bool.toNat_le _)
    _ = k := by simp
    _ ≤ 5 := hk

theorem sum_spread8_eq_digits {k : ℕ} (bs : Fin k → BitVec 8) :
    ∑ t, spread8 (bs t) = ∑ i : Fin 8, (∑ t, ((bs t).getLsbD i.val).toNat) * 6 ^ i.val := by
  simp only [spread8_eq_sum, Finset.sum_mul]
  exact Finset.sum_comm

theorem digit_of_sum {k : ℕ} (hk : k ≤ 5) (bs : Fin k → BitVec 8) (i : Fin 8) :
    (∑ t, spread8 (bs t)) / 6 ^ i.val % 6 = ∑ t, ((bs t).getLsbD i.val).toNat := by
  rw [sum_spread8_eq_digits]
  exact digit_of_digits (fun j : Fin 8 => ∑ t, ((bs t).getLsbD j.val).toNat)
    (fun j => Nat.lt_of_le_of_lt (bit_sum_le hk bs j.val) (by norm_num)) i

theorem sum_spread8_lt {k : ℕ} (hk : k ≤ 5) (bs : Fin k → BitVec 8) :
    ∑ t, spread8 (bs t) < 6 ^ 8 := by
  rw [sum_spread8_eq_digits]
  exact digits_lt _ (fun j => Nat.lt_of_le_of_lt (bit_sum_le hk bs j.val) (by norm_num))

theorem xorAll_getLsbD {w : ℕ} : ∀ {k : ℕ} (bs : Fin k → BitVec w) (i : ℕ),
    (xorAll bs).getLsbD i = decide ((∑ t, ((bs t).getLsbD i).toNat) % 2 = 1)
  | 0, _, i => by simp [xorAll]
  | k + 1, bs, i => by
    rw [xorAll, BitVec.getLsbD_xor, xorAll_getLsbD (fun t => bs t.succ) i, Fin.sum_univ_succ]
    cases (bs 0).getLsbD i <;>
      rcases Nat.mod_two_eq_zero_or_one (∑ t : Fin k, ((bs t.succ).getLsbD i).toNat) with h | h <;>
      simp [h, Nat.add_mod]

theorem parity_xor {k : ℕ} (bs : Fin k → BitVec 8) (i : ℕ) :
    (∑ t, ((bs t).getLsbD i).toNat) % 2 = ((xorAll bs).getLsbD i).toNat := by
  rw [xorAll_getLsbD]
  rcases Nat.mod_two_eq_zero_or_one (∑ t, ((bs t).getLsbD i).toNat) with h | h <;> simp [h]

theorem parityBits_lt : ∀ (n x : ℕ), parityBits n x < 2 ^ n
  | 0, _ => by simp [parityBits]
  | n + 1, x => by
    have := parityBits_lt n (x / 6)
    have : x % 6 % 2 < 2 := Nat.mod_lt _ (by norm_num)
    rw [parityBits, pow_succ]
    omega

theorem parityBits_testBit : ∀ (n x i : ℕ),
    (parityBits n x).testBit i = (decide (i < n) && decide (x / 6 ^ i % 6 % 2 = 1))
  | 0, _, i => by simp [parityBits]
  | n + 1, x, 0 => by
    rw [parityBits, Nat.testBit_zero]
    simp only [pow_zero, Nat.div_one, Nat.zero_lt_succ, decide_true, Bool.true_and]
    congr 1
    apply propext
    omega
  | n + 1, x, i + 1 => by
    rw [parityBits, Nat.testBit_succ]
    have : (x % 6 % 2 + 2 * parityBits n (x / 6)) / 2 = parityBits n (x / 6) := by omega
    rw [this, parityBits_testBit n (x / 6) i, pow_succ', ← Nat.div_div_eq_div_mul]
    simp

theorem parityBits_add : ∀ (a b x : ℕ),
    parityBits (a + b) x = parityBits a x + 2 ^ a * parityBits b (x / 6 ^ a)
  | 0, b, x => by simp [parityBits]
  | a + 1, b, x => by
    rw [Nat.add_right_comm, parityBits, parityBits, parityBits_add a b (x / 6),
      pow_succ', Nat.div_div_eq_div_mul, ← pow_succ']
    ring

theorem parityBits_mod : ∀ (n x : ℕ), parityBits n (x % 6 ^ n) = parityBits n x
  | 0, _ => by simp [parityBits]
  | n + 1, x => by
    rw [parityBits, parityBits, pow_succ', Nat.mod_mul_right_mod, Nat.mod_mul_right_div_self,
      parityBits_mod n (x / 6)]

theorem chunkParity_spec (c : ℕ) :
    chunkParity c = c % 6 % 2 + (c / 6) % 6 % 2 * 2 + (c / 36) % 6 % 2 * 4 + (c / 216) % 6 % 2 * 8 := by
  simp only [chunkParity, parityBits, Nat.div_div_eq_div_mul]
  omega

theorem parityBits_spread_sum {k : ℕ} (hk : k ≤ 5) (bs : Fin k → BitVec 8) :
    parityBits 8 (∑ t, spread8 (bs t)) = (xorAll bs).toNat := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [parityBits_testBit]
  by_cases hi : i < 8
  · rw [digit_of_sum hk bs ⟨i, hi⟩, parity_xor bs i]
    have : (xorAll bs).toNat.testBit i = (xorAll bs).getLsbD i := rfl
    rw [this]
    cases (xorAll bs).getLsbD i <;> simp [hi]
  · have hlt : (xorAll bs).toNat < 2 ^ i :=
      Nat.lt_of_lt_of_le (xorAll bs).isLt (Nat.pow_le_pow_right (by norm_num) (by omega))
    simp [hi, Nat.testBit_lt_two_pow hlt]

theorem chunks_unique {n : ℕ} (chunks : Fin n → ℕ) (hc : ∀ k, chunks k < 1296) (S : ℕ)
    (h : S = ∑ k, chunks k * 1296 ^ k.val) (k : Fin n) : chunks k = S / 1296 ^ k.val % 1296 := by
  rw [h]
  exact (digit_of_digits chunks hc k).symm

theorem getD_map_range {f : ℕ → ℕ} {n a : ℕ} (h : a < n) : ((List.range n).map f).getD a 0 = f a := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_range h]

theorem chunkParity_eq : AesTables.chunkParity = (List.range 1296).map chunkParity := by
  decide +kernel

theorem spreadBytes_eq : AesTables.spreadBytes = (List.range 256).map (spreadBits 8) := by
  decide +kernel

theorem chunksTable_spec (c : ℕ) (hc : c < 1296) : AesTables.chunkParity.getD c 0 = chunkParity c := by
  rw [chunkParity_eq, getD_map_range hc]

theorem bytesTable_spec (a : ℕ) (ha : a < 256) : AesTables.spreadBytes.getD a 0 = spreadBits 8 a := by
  rw [spreadBytes_eq, getD_map_range ha]

theorem bytesTable_spread8 (b : BitVec 8) :
    AesTables.spreadBytes.getD b.toNat 0 = spread8 b :=
  bytesTable_spec b.toNat b.isLt

theorem natCast_eq_of_lt {p a b : ℕ} (h : (a : ZMod p) = (b : ZMod p)) (ha : a < p) (hb : b < p) :
    a = b := by
  rw [ZMod.natCast_eq_natCast_iff'] at h
  rwa [Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] at h

section Field

variable {p : ℕ} [NeZero p]

/-- Semantics of the chunk-parity lookup, assumed from lookup-argument soundness. -/
def ChunkLookupSound (lookup : ZMod p → ZMod p → Prop) : Prop :=
  ∀ c n, lookup c n → c.val < 1296 ∧ n = ((AesTables.chunkParity.getD c.val 0 : ℕ) : ZMod p)

/-- Mirror of `decodeWordSum`: the hinted chunks recompose the spread sum, each
chunk is looked up in the parity table, and nibble pairs form the bytes. -/
def DecodeWord (lookup : ZMod p → ZMod p → Prop) (m : ℕ) (S : ZMod p)
    (chunks nibbles : Fin (2 * m) → ZMod p) (bytes : Fin m → ZMod p) : Prop :=
  S = ∑ k, chunks k * (1296 : ZMod p) ^ k.val ∧
  (∀ k, lookup (chunks k) (nibbles k)) ∧
  ∀ j : Fin m, bytes j = nibbles ⟨2 * j.val, by omega⟩ + nibbles ⟨2 * j.val + 1, by omega⟩ * 16

theorem decode_chunk_pair (X N j : ℕ) (hX : N / (6 ^ 8) ^ j % 6 ^ 8 = X) :
    N / 1296 ^ (2 * j) % 1296 = X % 6 ^ 4 ∧ N / 1296 ^ (2 * j + 1) % 1296 = X / 6 ^ 4 := by
  have h1296 : (1296 : ℕ) ^ (2 * j) = (6 ^ 8) ^ j := by
    rw [pow_mul]; norm_num
  constructor
  · rw [h1296, ← hX, Nat.mod_mod_of_dvd _ (by norm_num)]
    norm_num
  · rw [pow_succ, ← Nat.div_div_eq_div_mul, h1296, ← hX]
    generalize N / (6 ^ 8) ^ j = Y
    rw [show (6 : ℕ) ^ 8 = 1296 * 1296 by norm_num, show (6 : ℕ) ^ 4 = 1296 by norm_num,
      Nat.mod_mul_right_div_self]

theorem decodeWord_sound {m k : ℕ} (hp : 6 ^ 32 < p) (hm : m ≤ 4) (hk : k ≤ 5)
    (b : Fin m → Fin k → BitVec 8) {lookup : ZMod p → ZMod p → Prop}
    (hL : ChunkLookupSound lookup) {S : ZMod p} {chunks nibbles : Fin (2 * m) → ZMod p}
    {bytes : Fin m → ZMod p}
    (hin : S = ((∑ j : Fin m, (∑ t, spread8 (b j t)) * (6 ^ 8) ^ j.val : ℕ) : ZMod p))
    (h : DecodeWord lookup m S chunks nibbles bytes) :
    ∀ j, bytes j = ((xorAll (b j)).toNat : ZMod p) := by
  obtain ⟨hS, hlk, hby⟩ := h
  have hc : ∀ q, (chunks q).val < 1296 := fun q => (hL _ _ (hlk q)).1
  have hn : ∀ q, nibbles q = ((chunkParity (chunks q).val : ℕ) : ZMod p) := by
    intro q
    rw [(hL _ _ (hlk q)).2, chunksTable_spec _ (hc q)]
  set N := ∑ q : Fin (2 * m), (chunks q).val * 1296 ^ q.val with hNdef
  set M := ∑ j : Fin m, (∑ t, spread8 (b j t)) * (6 ^ 8) ^ j.val with hMdef
  have hX : ∀ j, (∑ t, spread8 (b j t)) < 6 ^ 8 := fun j => sum_spread8_lt hk (b j)
  have hbound : (6 : ℕ) ^ 32 ≥ (6 ^ 8) ^ m := by
    rw [← pow_mul]; exact Nat.pow_le_pow_right (by norm_num) (by omega)
  have hNlt : N < p := by
    have : N < 1296 ^ (2 * m) := digits_lt (fun q : Fin (2 * m) => (chunks q).val) hc
    have h2 : (1296 : ℕ) ^ (2 * m) ≤ 6 ^ 32 := by
      rw [show (1296 : ℕ) = 6 ^ 4 by norm_num, ← pow_mul]
      exact Nat.pow_le_pow_right (by norm_num) (by omega)
    omega
  have hMlt : M < p := by
    have : M < (6 ^ 8) ^ m := digits_lt (fun j : Fin m => ∑ t, spread8 (b j t)) hX
    omega
  have hNM : N = M := by
    apply natCast_eq_of_lt _ hNlt hMlt
    rw [← hin, hS, hNdef]
    push_cast
    simp only [ZMod.natCast_val, ZMod.cast_id', id]
  intro j
  have hdig : M / (6 ^ 8) ^ j.val % 6 ^ 8 = ∑ t, spread8 (b j t) :=
    digit_of_digits (fun j : Fin m => ∑ t, spread8 (b j t)) hX j
  obtain ⟨hlo, hhi⟩ := decode_chunk_pair _ M j.val hdig
  have hclo := chunks_unique (fun q : Fin (2 * m) => (chunks q).val) hc N rfl ⟨2 * j.val, by omega⟩
  have hchi := chunks_unique (fun q : Fin (2 * m) => (chunks q).val) hc N rfl
    ⟨2 * j.val + 1, by omega⟩
  simp only at hclo hchi
  rw [hNM, hlo] at hclo
  rw [hNM, hhi] at hchi
  rw [hby j, hn, hn, hclo, hchi, chunkParity, chunkParity, parityBits_mod,
    ← parityBits_spread_sum hk (b j), show (8 : ℕ) = 4 + 4 by rfl, parityBits_add]
  push_cast
  ring

end Field

end ZolanaVE.Aes
