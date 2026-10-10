import VerifiableEncryption.Envelope
import VerifiableEncryption.Curve.DerivePublicKey
import VerifiableEncryption.Curve.AgreeKey
import VerifiableEncryption.Aes.Sound

/-!
The top results restated with the lookup hypotheses bundled as
`LookupAssumptions`.
-/

namespace ZolanaVE

open ZolanaVE.P256 ZolanaVE.Field ZolanaVE.Aes ZolanaVE.Kdf ZolanaVE.Envelope

variable [Fact (Nat.Prime Order)]

theorem top_agreeKey_sound (hA : LookupAssumptions)
    {sk : List.Vector F 32} {pk : List.Vector F 65} {packed : List.Vector F 6}
    (h : AgreeKey_32_65_6 sk pk packed) :
    ∃ hQ : OnCurve ((bytesBE pk 1 32 : ℕ) : Fp) ((bytesBE pk 33 32 : ℕ) : Fp),
      pk.get 0 = 4 ∧ bytesBE pk 1 32 < p ∧ bytesBE pk 33 32 < p ∧
      ∃ (xS yS xE yE : ℕ) (hS : OnCurve (xS : Fp) (yS : Fp)) (hE : OnCurve (xE : Fp) (yE : Fp)),
        xS < p ∧ xE < p ∧ yE < p ∧
        mkPoint hS = (bytesBE sk 0 32 : ℤ) • mkPoint hQ ∧ mkPoint hE = (bytesBE sk 0 32 : ℤ) • G ∧
        packed.get 0 = (((2 + bytesBE pk 33 32 % 2) * 2 ^ 240 + bytesBE pk 1 32 / 2 ^ 16 : ℕ) : F) ∧
        packed.get 1 = ((bytesBE pk 1 32 % 2 ^ 16 : ℕ) : F) ∧
        packed.get 2 = (((2 + yE % 2) * 2 ^ 240 + xE / 2 ^ 16 : ℕ) : F) ∧
        packed.get 3 = ((xE % 2 ^ 16 : ℕ) : F) ∧
        packed.get 4 = ((xS / 2 ^ 8 : ℕ) : F) ∧
        packed.get 5 = ((xS % 2 ^ 8 : ℕ) : F) :=
  agreeKey_sound hA.range hA.rows h

theorem top_derivePublicKey_sound (hA : LookupAssumptions) {sk X : List.Vector F 32} {lo hi : F}
    (h : DerivePublicKey_32_32 sk X lo hi) :
    ∃ (xE yE : ℕ) (hE : OnCurve (xE : Fp) (yE : Fp)),
      ¬ (n : ℤ) ∣ (bytesBE sk 0 32 : ℤ) ∧ xE < p ∧ yE < p ∧
      mkPoint hE = (bytesBE sk 0 32 : ℤ) • G ∧
      bytesBE X 0 32 = xE ∧ (∀ i < 32, byteAt X i < 256) ∧
      lo = (((2 + yE % 2) * 2 ^ 240 + xE / 2 ^ 16 : ℕ) : F) ∧ hi = ((xE % 2 ^ 16 : ℕ) : F) :=
  derivePublicKey_sound hA.range h

theorem top_aesCtr_sound (hA : LookupAssumptions) {Key : List.Vector F 32} {Nonce : List.Vector F 12}
    {Plaintext Ciphertext : List.Vector F 16}
    (h : AesCtrBlock_32_12_16_16 Key Nonce Plaintext Ciphertext) :
    (∀ n, Key.get n = ((keyBytes Key n).toNat : F)) ∧
    (∀ n, Nonce.get n = ((bytesOf Nonce n).toNat : F)) ∧
    (∀ n, Plaintext.get n = ((bytesOf Plaintext n).toNat : F)) ∧
    (∀ n, Ciphertext.get n = ((bytesOf Ciphertext n).toNat : F)) ∧
    List.ofFn (bytesOf Ciphertext) =
      ctrEncrypt (keyBytes Key) (bytesOf Nonce) (List.ofFn (bytesOf Plaintext)) :=
  AesCtr_sound hA.aes h

end ZolanaVE
