import VerifiableEncryption.Top

/-!
Pinned axiom sets of the top theorems (results about P-256: Lean's three axioms, `bn254_Fr_prime` and the three P-256 axioms of `Assumptions.lean`). A change in the trusted base of
any of them fails this module.
-/

/-- info: 'ZolanaVE.top_agreeKey_sound' depends on axioms: [bn254_Fr_prime,
 propext,
 Classical.choice,
 Quot.sound,
 ZolanaVE.Assumptions.p256_order_prime,
 ZolanaVE.Assumptions.p256_point_order,
 ZolanaVE.Assumptions.p256_prime] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.top_agreeKey_sound

/-- info: 'ZolanaVE.top_derivePublicKey_sound' depends on axioms: [bn254_Fr_prime,
 propext,
 Classical.choice,
 Quot.sound,
 ZolanaVE.Assumptions.p256_order_prime,
 ZolanaVE.Assumptions.p256_point_order,
 ZolanaVE.Assumptions.p256_prime] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.top_derivePublicKey_sound

/-- info: 'ZolanaVE.P256.agreeKey_sound' depends on axioms: [bn254_Fr_prime,
 propext,
 Classical.choice,
 Quot.sound,
 ZolanaVE.Assumptions.p256_order_prime,
 ZolanaVE.Assumptions.p256_point_order,
 ZolanaVE.Assumptions.p256_prime] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.P256.agreeKey_sound

/-- info: 'ZolanaVE.P256.derivePublicKey_sound' depends on axioms: [bn254_Fr_prime,
 propext,
 Classical.choice,
 Quot.sound,
 ZolanaVE.Assumptions.p256_order_prime,
 ZolanaVE.Assumptions.p256_point_order,
 ZolanaVE.Assumptions.p256_prime] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.P256.derivePublicKey_sound

/-- info: 'ZolanaVE.P256.scalarMulChecked_sound' depends on axioms: [bn254_Fr_prime,
 propext,
 Classical.choice,
 Quot.sound,
 ZolanaVE.Assumptions.p256_order_prime,
 ZolanaVE.Assumptions.p256_point_order,
 ZolanaVE.Assumptions.p256_prime] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.P256.scalarMulChecked_sound

/-- info: 'ZolanaVE.P256.scalarMulBase_sound' depends on axioms: [bn254_Fr_prime,
 propext,
 Classical.choice,
 Quot.sound,
 ZolanaVE.Assumptions.p256_order_prime,
 ZolanaVE.Assumptions.p256_point_order,
 ZolanaVE.Assumptions.p256_prime] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.P256.scalarMulBase_sound

/-- info: 'ZolanaVE.Envelope.envelope16_sound' depends on axioms: [bn254_Fr_prime,
 propext,
 Classical.choice,
 Quot.sound,
 ZolanaVE.Assumptions.p256_order_prime,
 ZolanaVE.Assumptions.p256_point_order,
 ZolanaVE.Assumptions.p256_prime] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.Envelope.envelope16_sound

/-- info: 'ZolanaVE.Envelope.envelopeMerge_sound' depends on axioms: [bn254_Fr_prime,
 propext,
 Classical.choice,
 Quot.sound,
 ZolanaVE.Assumptions.p256_order_prime,
 ZolanaVE.Assumptions.p256_point_order,
 ZolanaVE.Assumptions.p256_prime] -/
#guard_msgs (whitespace := lax) in
#print axioms ZolanaVE.Envelope.envelopeMerge_sound
