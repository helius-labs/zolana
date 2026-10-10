import VerifiableEncryption.Envelope.Bodies
import VerifiableEncryption.Kdf.KeySchedule
import VerifiableEncryption.Aes.EnvelopeAes

/-!
The KDF segment shared by both envelopes: the AES key fed to the key expansion
and the nonce bytes are `kdf poseidon sharedSecret "TMEC"`.
-/

set_option linter.unusedSectionVars false

namespace ZolanaVE.Envelope

open ZolanaVE ZolanaVE.Kdf ZolanaVE.Aes

variable [Fact (Nat.Prime Order)]

/-- AES-256 key bytes derived from a shared secret. -/
def kdfKey (ss : F) : Fin 32 → Byte := fun i => BitVec.ofNat 8 ((kdf poseidon ss tmecInfo).1 i)

/-- CTR nonce bytes derived from a shared secret. -/
def kdfNonce (ss : F) : Fin 12 → Byte := fun j => BitVec.ofNat 8 ((kdf poseidon ss tmecInfo).2 j)

lemma kdf_key_lt (ss : F) (i : Fin 32) : (kdf poseidon ss tmecInfo).1 i < Order := by
  have h : (kdf poseidon ss tmecInfo).1 i < 2 ^ 8 := by
    simp only [kdf]
    split <;> exact byteOf_lt _ _
  have : 2 ^ 8 < Order := by decide
  omega

lemma byteOf_lt_order (x : ℕ) (i : Fin 32) : byteOf x i < Order := by
  have := byteOf_lt x i
  have : 2 ^ 8 < Order := by decide
  omega

set_option maxHeartbeats 4000000 in
theorem kdfAesHead_sound {ss : F}
    {P : List.Vector F 32 → List.Vector (List.Vector F 240) 2 → F → F → Prop}
    (h : KdfAesHead ss P) :
    ∃ Key Nb : List.Vector F 32, keyBytes Key = kdfKey ss ∧ nonceOf Nb = kdfNonce ss ∧
      AesKeyExpansion_32 Key fun g397 => SpreadByteLookup (Nb.get 20) fun g398 =>
        SpreadByteLookup (Nb.get 21) fun g399 => P Nb g397 g398 g399 := by
  unfold KdfAesHead at h
  obtain ⟨g0, e0, g1, e1, g2, e2, g3, e3, g4, e4, g5, e5, g6, e6, g7, e7, h⟩ := h
  have hpack : g7 = ((1414350147 : ℕ) : F) := by
    subst e0 e1 e2 e3 e4 e5 e6 e7
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
    norm_num
  subst hpack
  simp only [Poseidon_3_rw, Poseidon_2_rw, Nat.cast_ofNat] at h
  replace h := FieldBytesBE_32_sound h
  beta_reduce at h
  replace h := FieldBytesBE_32_sound h
  beta_reduce at h
  replace h := FieldBytesBE_32_sound h
  beta_reduce at h
  have hsilo : poseidon ((domSepSilo : F) :: ss :: (packBE31 tmecInfo).map (Nat.cast : ℕ → F)) =
      poseidon₃ vec![(1414353737 : F), ss, (1414350147 : F)] := by
    rw [packBE31_tmec]
    simp only [domSepSilo, List.map, Nat.cast_ofNat]
    rfl
  refine ⟨_, _, ?_, ?_, h⟩
  · funext i
    unfold keyBytes kdfKey
    congr 1
    rw [← ZMod.val_cast_of_lt (kdf_key_lt ss i)]
    congr 1
    simp only [kdf, hsilo, poseidon_list2, domSepKey, domSepKeyHi, Nat.cast_ofNat]
    fin_cases i
    all_goals first
      | (rw [dif_pos (by decide)]; rfl)
      | (rw [dif_neg (by decide)]; rfl)
  · funext j
    unfold nonceOf kdfNonce
    congr 1
    rw [List.Vector.get_ofFn, ZMod.val_cast_of_lt (byteOf_lt_order _ _)]
    simp only [kdf, hsilo, poseidon_list2, domSepNonce, Nat.cast_ofNat]
    congr 1
    exact Fin.ext (Nat.add_comm _ _)

end ZolanaVE.Envelope
