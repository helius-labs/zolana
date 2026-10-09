import VerifiableEncryption.Aes.CtrBlock

/-!
Top-level AES statements against `Spec.lean`, under the lookup semantics
`AesLookupSem`.
-/

namespace ZolanaVE.Aes

open ZolanaVE

variable [Fact (Nat.Prime Order)]

/-- The extracted AES-256 key schedule returns, in order, the spread and plain
bytes of FIPS-197 `keyExpansion256` of its key bytes; byte `n` is byte `n % 4`
of word `n / 4`. -/
theorem keyExpansion_correct (hL : AesLookupSem) {Key : List.Vector F 32}
    {k : List.Vector (List.Vector F 240) 2 → Prop} (h : AesKeyExpansion_32 Key k) :
    (∀ n, Key.get n = ((keyBytes Key n).toNat : F)) ∧
      k vec![List.Vector.ofFn fun n => (spread8 (rkByte (keyExpansion256 (keyBytes Key)) n) : F),
        List.Vector.ofFn fun n => ((rkByte (keyExpansion256 (keyBytes Key)) n).toNat : F)] :=
  keyExpansion_cps hL h

theorem bytesOf_natCast {m : ℕ} {v : List.Vector F m} {i : Fin m} {b : Byte}
    (h : v.get i = (b.toNat : F)) : bytesOf v i = b := by
  have hb := b.isLt
  have hlt : b.toNat < Order := lt_trans hb (by unfold Order; norm_num)
  rw [bytesOf, h, ZMod.val_natCast, Nat.mod_eq_of_lt hlt, BitVec.ofNat_toNat, BitVec.setWidth_eq]

theorem ctrEncrypt_one_block (key : Fin 32 → Byte) (nonce : Fin 12 → Byte) (pt : Fin 16 → Byte) :
    ctrEncrypt key nonce (List.ofFn pt) =
      List.ofFn fun i => pt i ^^^ encryptBlock key (counterBlock nonce 2) i := by
  simp only [ctrEncrypt, ctrGeneric, List.length_ofFn]
  show ctrBlocks _ _ 1 _ = _
  simp only [ctrBlocks, List.append_nil]
  rw [List.take_of_length_le (by simp)]
  apply List.ext_get
  · simp
  · intro n h1 h2
    simp

/-- AES-256-CTR soundness of the extracted one-block gadget: its key, nonce and
plaintext are byte-valued, and its ciphertext bytes are `ctrEncrypt` of the
plaintext under that key and nonce, starting at counter 2. -/
theorem AesCtr_sound (hL : AesLookupSem) {Key : List.Vector F 32} {Nonce : List.Vector F 12}
    {Plaintext Ciphertext : List.Vector F 16}
    (h : AesCtrBlock_32_12_16_16 Key Nonce Plaintext Ciphertext) :
    (∀ n, Key.get n = ((keyBytes Key n).toNat : F)) ∧
    (∀ n, Nonce.get n = ((bytesOf Nonce n).toNat : F)) ∧
    (∀ n, Plaintext.get n = ((bytesOf Plaintext n).toNat : F)) ∧
    (∀ n, Ciphertext.get n = ((bytesOf Ciphertext n).toNat : F)) ∧
    List.ofFn (bytesOf Ciphertext) =
      ctrEncrypt (keyBytes Key) (bytesOf Nonce) (List.ofFn (bytesOf Plaintext)) := by
  obtain ⟨hk, hn, hp, hc⟩ := aesCtrBlock_cps hL h
  have hcb : ∀ i, bytesOf Ciphertext i =
      encryptBlock (keyBytes Key) (counterBlock (bytesOf Nonce) 2) i ^^^ bytesOf Plaintext i :=
    fun i => bytesOf_natCast (hc i)
  refine ⟨hk, hn, hp, fun n => by rw [hcb n, hc n], ?_⟩
  rw [ctrEncrypt_one_block]
  congr 1
  funext i
  rw [hcb i, BitVec.xor_comm]

end ZolanaVE.Aes
