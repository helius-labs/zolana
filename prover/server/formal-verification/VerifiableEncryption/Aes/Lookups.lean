import VerifiableEncryption.Circuit.Aes
import VerifiableEncryption.Aes.Round

/-!
Semantics of the opaque AES lookups of the extracted circuit. They are
hypotheses, not axioms: each states that a satisfied lookup has its index in
range and continues with the table row of `AesTables.lean` at that index, which
is gnark `logderivlookup` soundness for tables built from the same rows
(`TestTableAccessorsMatchLookupRows`).
-/

namespace ZolanaVE.Aes

open ZolanaVE

variable [Fact (Nat.Prime Order)]

def SpreadByteLookupSem : Prop :=
  ∀ (a : F) (k : F → Prop), SpreadByteLookup a k →
    a.val < 256 ∧ k ((AesTables.spreadBytes.getD a.val 0 : ℕ) : F)

def SubstitutionLookupSem : Prop :=
  ∀ (i : F) (k : F → Prop), SubstitutionLookup i k → i.val < 1280 ∧ k ((substitutionAt i.val : ℕ) : F)

def ChunkParityLookupSem : Prop :=
  ∀ (c : F) (k : F → Prop), ChunkParityLookup c k →
    c.val < 1296 ∧ k ((AesTables.chunkParity.getD c.val 0 : ℕ) : F)

structure AesLookupSem : Prop where
  spread : SpreadByteLookupSem
  subst : SubstitutionLookupSem
  chunk : ChunkParityLookupSem

def chunkRel (c n : F) : Prop := c.val < 1296 ∧ n = ((AesTables.chunkParity.getD c.val 0 : ℕ) : F)

def substRel (i out : F) : Prop := i.val < 1280 ∧ out = ((substitutionAt i.val : ℕ) : F)

def spreadRel (a out : F) : Prop := a.val < 256 ∧ out = ((AesTables.spreadBytes.getD a.val 0 : ℕ) : F)

theorem chunkRel_sound : ChunkLookupSound (p := Order) chunkRel := fun _ _ h => h

theorem substRel_sound : SubstLookupSound (p := Order) substRel := fun _ _ h => h

theorem spreadRel_sound : SpreadByteLookupSound (p := Order) spreadRel := fun _ _ h => h

omit [Fact (Nat.Prime Order)] in
theorem order_gt : 6 ^ 32 < Order := by
  unfold Order
  norm_num

theorem gate_add (a b : F) : Gates.add a b = a + b := rfl

theorem gate_mul (a b : F) : Gates.mul a b = a * b := rfl

theorem gate_eq (a b : F) : Gates.eq a b = (a = b) := rfl

theorem spreadByte_step (hL : SpreadByteLookupSem) {a : F} {k : F → Prop} (h : SpreadByteLookup a k) :
    ∃ b : Byte, a = (b.toNat : F) ∧ k (spread8 b : F) := by
  obtain ⟨ha, hk⟩ := hL a k h
  obtain ⟨b, hb, hout⟩ := spreadByte_of_lookup spreadRel_sound ⟨ha, rfl⟩
  exact ⟨b, hb, hout ▸ hk⟩

theorem spreadByte_step_of (hL : SpreadByteLookupSem) (b : Byte) {a : F} (hab : a = (b.toNat : F))
    {k : F → Prop} (h : SpreadByteLookup a k) : k (spread8 b : F) := by
  obtain ⟨_, hk⟩ := hL a k h
  have := spreadByte_correct (lt_trans (by norm_num) order_gt) spreadRel_sound b
    (out := ((AesTables.spreadBytes.getD a.val 0 : ℕ) : F)) (by rw [← hab]; exact ⟨by assumption, rfl⟩)
  rwa [this] at hk

theorem subst_step (hL : SubstitutionLookupSem) (r : Fin 4) (b : Byte) {a i : F}
    (hab : a = (b.toNat : F)) (hi : i = a + ((256 * r.val : ℕ) : F)) {k : F → Prop}
    (h : SubstitutionLookup i k) : k (spreadWord (fun j => mixByte r j (sb b)) : F) := by
  obtain ⟨hlt, hk⟩ := hL i k h
  have := subst_mix (lt_trans (by norm_num) order_gt) substRel_sound r b
    (out := ((substitutionAt i.val : ℕ) : F)) (by rw [← hab, ← hi]; exact ⟨hlt, rfl⟩)
  rwa [this] at hk

theorem sbox_step (hL : SubstitutionLookupSem) (b : Byte) {a i : F}
    (hab : a = (b.toNat : F)) (hi : i = a + ((256 * 4 : ℕ) : F)) {k : F → Prop}
    (h : SubstitutionLookup i k) : k (spread8 (sb b) : F) := by
  obtain ⟨hlt, hk⟩ := hL i k h
  have := subst_sbox (lt_trans (by norm_num) order_gt) substRel_sound b
    (out := ((substitutionAt i.val : ℕ) : F)) (by rw [← hab, ← hi]; exact ⟨hlt, rfl⟩)
  rwa [this] at hk

theorem chunk_step (hL : ChunkParityLookupSem) {c : F} {k : F → Prop} (h : ChunkParityLookup c k) :
    ∃ n, chunkRel c n ∧ k n := by
  obtain ⟨hc, hk⟩ := hL c k h
  exact ⟨_, ⟨hc, rfl⟩, hk⟩

end ZolanaVE.Aes
