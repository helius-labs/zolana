import VerifiableEncryption.Top

/-!
Pinned axiom sets of the top theorems (AES and KDF results: Lean's three axioms, `bn254_Fr_prime` where the native field instance is used). A change in the trusted base of
any of them fails this module.
-/

/-- info: 'ZolanaVE.top_aesCtr_sound' depends on axioms: [bn254_Fr_prime, propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.top_aesCtr_sound

/-- info: 'ZolanaVE.Aes.AesCtr_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.Aes.AesCtr_sound

/-- info: 'ZolanaVE.Kdf.KeySchedule_32_12_sound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.Kdf.KeySchedule_32_12_sound
