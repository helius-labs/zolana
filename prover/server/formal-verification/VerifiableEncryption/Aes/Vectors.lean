import VerifiableEncryption.Aes.Spec

/-
Known-answer tests for `Aes.Spec`.

The kernel evaluates by need without sharing, so evaluating `encryptBlock` directly re-evaluates
every earlier round once per byte that reads it, which grows by a factor of about five per round.
The `*Fast` definitions below route every round state and key word through a single natural
number (`packBytes`). The kernel caches the normal form of that closed `Nat` term, so each round is
evaluated once. Each `*Fast` definition is proven equal to its spec counterpart, and every vector
theorem is stated against the spec.

One block costs the kernel about 3 GB of cache, which is released between declarations, so each
counter-mode keystream block is its own theorem and the mode theorems only rewrite with them.

Sources: FIPS-197 Appendix A.3 and C.3, and the McGrew-Viega GCM specification test cases 14 and
16 (the SP 800-38D reference vectors, including the `E(K, Y_i)` keystream blocks), read from the
published PDFs. SP 800-38A F.5.5 is taken from Go's crypto/cipher tests (`ctr_aes_test.go`,
`common_test.go`, citing SP 800-38A); its keystream blocks are plaintext XOR ciphertext.
-/
namespace ZolanaVE.Aes

def packBytes : List Byte → Nat
  | [] => 0
  | b :: bs => b.toNat + 256 * packBytes bs

theorem packBytes_digit (bs : List Byte) (i : Nat) (h : i < bs.length) :
    BitVec.ofNat 8 (packBytes bs / 256 ^ i) = bs[i] := by
  induction bs generalizing i with
  | nil => simp at h
  | cons b bs ih =>
    cases i with
    | zero =>
      apply BitVec.eq_of_toNat_eq
      have hb := b.isLt
      simp only [packBytes, Nat.pow_zero, Nat.div_one, BitVec.toNat_ofNat, List.getElem_cons_zero]
      omega
    | succ i =>
      have hdiv : (b.toNat + 256 * packBytes bs) / 256 = packBytes bs := by
        have hb := b.isLt
        omega
      simp only [List.length_cons] at h
      simp only [packBytes, Nat.pow_succ', ← Nat.div_div_eq_div_mul, hdiv,
        List.getElem_cons_succ]
      exact ih i (by omega)

def forceBytes {n : Nat} (f : Fin n → Byte) : Fin n → Byte :=
  fun i => BitVec.ofNat 8 (packBytes (List.ofFn f) / 256 ^ i.val)

theorem forceBytes_eq {n : Nat} (f : Fin n → Byte) : forceBytes f = f := by
  funext i
  simp only [forceBytes]
  rw [packBytes_digit _ _ (by simp)]
  simp

def keyWordsFast (key : Fin 32 → Byte) : Nat → List Word
  | 0 => []
  | n + 1 => keyWordsFast key n ++ [forceBytes (nextKeyWord key (keyWordsFast key n) n)]

theorem keyWordsFast_eq (key : Fin 32 → Byte) (n : Nat) : keyWordsFast key n = keyWords key n := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [keyWordsFast, keyWords, ih, forceBytes_eq]

def keyExpansionFast (key : Fin 32 → Byte) : Fin 60 → Word :=
  fun i => (keyWordsFast key 60).getD i.val zeroWord

theorem keyExpansionFast_eq (key : Fin 32 → Byte) : keyExpansionFast key = keyExpansion256 key := by
  funext i
  simp only [keyExpansionFast, keyExpansion256, keyWordsFast_eq]

def roundsFast (w : Fin 60 → Word) (blk : Block) : Nat → State
  | 0 => forceBytes (addRoundKey blk (roundKey w 0))
  | n + 1 => forceBytes (cipherRound w ⟨min (n + 1) 14, by omega⟩ (roundsFast w blk n))

theorem roundsFast_eq (w : Fin 60 → Word) (blk : Block) (n : Nat) :
    roundsFast w blk n = roundsFrom w blk n := by
  induction n with
  | zero => simp only [roundsFast, roundsFrom, forceBytes_eq]
  | succ n ih => simp only [roundsFast, roundsFrom, ih, forceBytes_eq]

def encryptFast (key : Fin 32 → Byte) (blk : Block) : Block :=
  let w := keyExpansionFast key
  forceBytes (finalRound w (roundsFast w blk 13))

theorem encryptFast_eq (key : Fin 32 → Byte) : encryptFast key = encryptBlock key := by
  funext blk
  simp only [encryptFast, encryptBlock, encryptWith, keyExpansionFast_eq, roundsFast_eq,
    forceBytes_eq]

def bytes (l : List Nat) : List Byte := l.map (BitVec.ofNat 8)

def block (l : List Nat) : Block := fun i => BitVec.ofNat 8 (l.getD i.val 0)

def key256 (l : List Nat) : Fin 32 → Byte := fun i => BitVec.ofNat 8 (l.getD i.val 0)

def nonce96 (l : List Nat) : Fin 12 → Byte := fun i => BitVec.ofNat 8 (l.getD i.val 0)

def wordToNat (w : Word) : Nat :=
  (w 0).toNat * 2 ^ 24 + (w 1).toNat * 2 ^ 16 + (w 2).toNat * 2 ^ 8 + (w 3).toNat

/-! FIPS-197 Appendix A.3: expansion of a 256-bit cipher key. -/

def fips197A3Key : Fin 32 → Byte := key256 [
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]

theorem fips197_a3 : (List.ofFn (keyExpansion256 fips197A3Key)).map wordToNat = [
    0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
    0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a,
    0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
    0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464, 0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214,
    0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
    0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
    0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
    0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e] := by
  rw [← keyExpansionFast_eq]
  decide +kernel

/-! FIPS-197 Appendix C.3: AES-256 cipher example. -/

def fips197C3Key : Fin 32 → Byte := key256 (List.range 32)

def fips197C3Plaintext : Block := block [
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]

theorem fips197_c3 : List.ofFn (encryptBlock fips197C3Key fips197C3Plaintext) = bytes [
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89] := by
  rw [← encryptFast_eq]
  decide +kernel

/-! SP 800-38A F.5.5: CTR-AES256.Encrypt. -/

def sp80038aKey : Fin 32 → Byte := fips197A3Key

def sp80038aCounter : Block := block [
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]

def sp80038aPlaintext : List Byte := bytes [
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10]

def sp80038aCiphertext : List Byte := bytes [
  0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
  0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
  0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
  0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6]

theorem sp800_38a_f55_block1 : List.ofFn (encryptBlock sp80038aKey sp80038aCounter) = bytes [
    0x0b, 0xdf, 0x7d, 0xf1, 0x59, 0x17, 0x16, 0x33, 0x5e, 0x9a, 0x8b, 0x15, 0xc8, 0x60, 0xc5, 0x02] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem sp800_38a_f55_block2 :
    List.ofFn (encryptBlock sp80038aKey (inc32 sp80038aCounter)) = bytes [
      0x5a, 0x6e, 0x69, 0x9d, 0x53, 0x61, 0x19, 0x06, 0x54, 0x33, 0x86, 0x3c, 0x8f, 0x65, 0x7b, 0x94] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem sp800_38a_f55_block3 :
    List.ofFn (encryptBlock sp80038aKey (inc32 (inc32 sp80038aCounter))) = bytes [
      0x1b, 0xc1, 0x2c, 0x9c, 0x01, 0x61, 0x0d, 0x5d, 0x0d, 0x8b, 0xd6, 0xa3, 0x37, 0x8e, 0xca, 0x62] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem sp800_38a_f55_block4 :
    List.ofFn (encryptBlock sp80038aKey (inc32 (inc32 (inc32 sp80038aCounter)))) = bytes [
      0x29, 0x56, 0xe1, 0xc8, 0x69, 0x35, 0x36, 0xb1, 0xbe, 0xe9, 0x9c, 0x73, 0xa3, 0x15, 0x76, 0xb6] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem sp800_38a_f55 :
    ctrGeneric sp80038aKey sp80038aCounter sp80038aPlaintext = sp80038aCiphertext := by
  rw [ctrGeneric, show (sp80038aPlaintext.length + 15) / 16 = 4 from rfl]
  simp only [ctrBlocks, sp800_38a_f55_block1, sp800_38a_f55_block2, sp800_38a_f55_block3,
    sp800_38a_f55_block4]
  decide +kernel

/-! GCM test case 14: AES-256, 96-bit IV, one zero block. -/

def gcmTc14Key : Fin 32 → Byte := key256 []

def gcmTc14Nonce : Fin 12 → Byte := nonce96 []

def gcmTc14Plaintext : List Byte := bytes (List.replicate 16 0)

def gcmTc14Ciphertext : List Byte := bytes [
  0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18]

theorem gcm_tc14_block1 : List.ofFn (encryptBlock gcmTc14Key (counterBlock gcmTc14Nonce 2)) = bytes [
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem gcm_tc14 : ctrEncrypt gcmTc14Key gcmTc14Nonce gcmTc14Plaintext = gcmTc14Ciphertext := by
  rw [ctrEncrypt, ctrGeneric, show (gcmTc14Plaintext.length + 15) / 16 = 1 from rfl]
  simp only [ctrBlocks, gcm_tc14_block1]
  decide +kernel

/-! GCM test case 16: AES-256, 96-bit IV, 60-byte plaintext (partial final block). -/

def gcmTc16Key : Fin 32 → Byte := key256 [
  0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
  0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08]

def gcmTc16Nonce : Fin 12 → Byte := nonce96 [
  0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88]

def gcmTc16Plaintext : List Byte := bytes [
  0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
  0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
  0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
  0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39]

def gcmTc16Ciphertext : List Byte := bytes [
  0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
  0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
  0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
  0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62]

theorem gcm_tc16_block1 : List.ofFn (encryptBlock gcmTc16Key (counterBlock gcmTc16Nonce 2)) = bytes [
    0x8b, 0x1c, 0xf3, 0xd5, 0x61, 0xd2, 0x7b, 0xe2, 0x51, 0x26, 0x3e, 0x66, 0x85, 0x71, 0x64, 0xe7] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem gcm_tc16_block2 :
    List.ofFn (encryptBlock gcmTc16Key (inc32 (counterBlock gcmTc16Nonce 2))) = bytes [
      0xe2, 0x9d, 0x25, 0x8f, 0xaa, 0xd1, 0x37, 0x13, 0x5b, 0xd4, 0x92, 0x80, 0xaf, 0x64, 0x5b, 0xd8] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem gcm_tc16_block3 :
    List.ofFn (encryptBlock gcmTc16Key (inc32 (inc32 (counterBlock gcmTc16Nonce 2)))) = bytes [
      0x90, 0x8c, 0x82, 0xdd, 0xcc, 0x65, 0xb2, 0x6e, 0x88, 0x7f, 0x85, 0x34, 0x1f, 0x24, 0x3d, 0x1d] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem gcm_tc16_block4 :
    List.ofFn (encryptBlock gcmTc16Key (inc32 (inc32 (inc32 (counterBlock gcmTc16Nonce 2))))) = bytes [
      0x74, 0x9c, 0xf3, 0x96, 0x39, 0xb7, 0x9c, 0x5d, 0x06, 0xaa, 0x8d, 0x5b, 0x93, 0x2f, 0xc7, 0xf8] := by
  rw [← encryptFast_eq]
  decide +kernel

theorem gcm_tc16 : ctrEncrypt gcmTc16Key gcmTc16Nonce gcmTc16Plaintext = gcmTc16Ciphertext := by
  rw [ctrEncrypt, ctrGeneric, show (gcmTc16Plaintext.length + 15) / 16 = 4 from rfl]
  simp only [ctrBlocks, gcm_tc16_block1, gcm_tc16_block2, gcm_tc16_block3, gcm_tc16_block4]
  decide +kernel

/-- The GCM counter blocks are `nonce ‖ BE32(2 + i)`: `inc32` steps the 32-bit counter. -/
theorem gcm_tc16_counters :
    List.ofFn (inc32 (inc32 (inc32 (counterBlock gcmTc16Nonce 2)))) =
      List.ofFn (counterBlock gcmTc16Nonce 5) := by
  decide +kernel

end ZolanaVE.Aes
