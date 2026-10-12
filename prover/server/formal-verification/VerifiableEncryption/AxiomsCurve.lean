import VerifiableEncryption.Top

/-!
Pinned axiom sets of the top theorems (results about P-256: Lean's three logical axioms; parameter and point-order facts have independent certificate proof source). A change in the trusted base of
any of them fails this module.
-/

/-- info: 'ZolanaVE.top_agreeKey_sound' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.top_agreeKey_sound

/-- info: 'ZolanaVE.top_derivePublicKey_sound' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.top_derivePublicKey_sound

/-- info: 'ZolanaVE.P256.agreeKey_sound' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.P256.agreeKey_sound

/-- info: 'ZolanaVE.P256.derivePublicKey_sound' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.P256.derivePublicKey_sound

/-- info: 'ZolanaVE.P256.scalarMulChecked_sound' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.P256.scalarMulChecked_sound

/-- info: 'ZolanaVE.P256.scalarMulBase_sound' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.P256.scalarMulBase_sound

/-- info: 'ZolanaVE.Envelope.envelope16_sound' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.Envelope.envelope16_sound

/-- info: 'ZolanaVE.Envelope.envelopeMerge_sound' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.Envelope.envelopeMerge_sound
