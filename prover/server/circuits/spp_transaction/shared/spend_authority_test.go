package shared_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// Spending is authorized by an EdDSA-Poseidon signature over the transaction's
// private hash, under the public key the UTXO's owner hash commits to, plus a
// binding that the nullifier secret is that key's discrete log. These tests pin
// each half: without the signature checks anyone could spend, and without the
// binding the owner could derive unlimited nullifiers for one UTXO and spend it
// repeatedly.

func spendAuthorityShape() protocol.Shape {
	return protocol.Shape{NInputs: 1, NOutputs: 2}
}

// buildSpendAuthorityAssignment is the baseline every case below mutates. The
// assertion that it solves first is what stops a case from passing merely
// because its signature went stale.
func buildSpendAuthorityAssignment(t testing.TB) *testAssignment {
	t.Helper()
	return buildCircuitAssignment(t, spendAuthorityShape())
}

func assertSpendAuthorityFails(t *testing.T, mutate func(t *testing.T, a *testAssignment)) {
	t.Helper()
	assert := test.NewAssert(t)
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(spendAuthorityShape()))

	baseline := buildSpendAuthorityAssignment(t)
	assert.SolvingSucceeded(circuit, asCustomZoneEddsaOnly(baseline), test.WithCurves(ecc.BN254))

	assignment := buildSpendAuthorityAssignment(t)
	mutate(t, assignment)
	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A signature from the wrong key cannot spend.
func TestSpendRejectsSignatureFromAnotherKey(t *testing.T) {
	assertSpendAuthorityFails(t, func(t *testing.T, a *testAssignment) {
		other := spptest.MustSpendKey(t, spptest.Fe(4242))
		message := spptest.AsBigInt(a.PrivateTxHash)
		a.Inputs[0].SpendSignature = spendSignatureVar(spptest.MustSignSpend(t, other, message, 0))
	})
}

// A signature over a different message cannot be replayed into this
// transaction, which is what binds the spend to these inputs and outputs.
func TestSpendRejectsSignatureOverAnotherMessage(t *testing.T) {
	assertSpendAuthorityFails(t, func(t *testing.T, a *testAssignment) {
		key := a.Inputs[0].SpendKey
		other := new(big.Int).Add(spptest.AsBigInt(a.PrivateTxHash), big.NewInt(1))
		a.Inputs[0].SpendSignature = spendSignatureVar(spptest.MustSignSpend(t, key, other, 0))
	})
}

// The neutral key verifies against a signature anyone can forge, so a real UTXO
// must not commit to it. Without this gate the forgery below is a free spend.
func TestSpendRejectsNeutralKeyOnRealUtxo(t *testing.T) {
	assertSpendAuthorityFails(t, func(t *testing.T, a *testAssignment) {
		// Everything else is made consistent with the neutral key -- owner hash,
		// nullifier, trees, public input hash -- so the non-identity gate is the
		// only constraint left to reject this witness. The identity signature the
		// slot then carries is one anyone can produce.
		a.Inputs[0].SpendKey = protocol.SpendKey{Secret: big.NewInt(0), Public: protocol.IdentitySpendPoint()}
		a.Inputs[0].SpendPublic = spendPublicVar(protocol.IdentitySpendPoint())
		a.Inputs[0].NullifierSecret = big.NewInt(0)
		a.Inputs[0].Utxo.Owner = spptest.MustOwnerHash(
			t,
			spptest.AsBigInt(a.Inputs[0].OwnerPkHash),
			protocol.IdentitySpendPoint(),
		)
		rebuildAfterOwnerChange(t, a)
	})
}

// The subgroup order is 251 bits and the scalar field 254, so secret and
// secret+order share a public key and a signature while deriving different
// nullifiers. The 250-bit range check on the secret is what closes that
// double-spend; this is the test that proves it.
func TestSpendRejectsSecretAliasedByGroupOrder(t *testing.T) {
	assertSpendAuthorityFails(t, func(t *testing.T, a *testAssignment) {
		secret := spptest.AsBigInt(a.Inputs[0].NullifierSecret)
		aliased := new(big.Int).Add(secret, protocol.SpendKeyOrder())
		a.Inputs[0].NullifierSecret = aliased
		// Everything else stays valid: same public key, same owner hash, same
		// signature. Only the nullifier moves, which is precisely the attack.
		nullifier := spptest.MustNullifier(
			t,
			spptest.MustUtxoHash(t, circuitFieldsToUtxo(a.Inputs[0].Utxo)),
			spptest.AsBigInt(a.Inputs[0].Utxo.Blinding),
			aliased,
		)
		a.Inputs[0].Nullifier = nullifier
		nfWitness := spptest.MustNonInclusion(t, spptest.MustNewNullifierTree(t), nullifier)
		a.Inputs[0].NullifierLowValue = nfWitness.LowValue
		a.Inputs[0].NullifierNextValue = nfWitness.NextValue
		fillStateProofElements(a.Inputs[0].NullifierLowPathElements, nfWitness.PathElements)
		a.Inputs[0].NullifierLowPathIndex = new(big.Int).SetUint64(nfWitness.LowIndex)
		refreshPublicInputHash(t, a)
	})
}

// gnark's verifier does not check that the witnessed public key is on the
// curve, so the circuit does it.
func TestSpendRejectsOffCurvePublicKey(t *testing.T) {
	assertSpendAuthorityFails(t, func(t *testing.T, a *testAssignment) {
		public := a.Inputs[0].SpendKey.Public
		offCurve := protocol.SpendPoint{
			X: new(big.Int).Add(public.X, big.NewInt(1)),
			Y: new(big.Int).Set(public.Y),
		}
		a.Inputs[0].SpendPublic = spendPublicVar(offCurve)
	})
}

// A dummy slot must carry the neutral key. An attacker-chosen key there would
// give padding an unconstrained identity, and the slot's secret is pinned to
// zero so no signature could authorize it anyway.
func TestDummyInputRejectsNonNeutralSpendKey(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(protocol.Shape{NInputs: 1, NOutputs: 2}))

	baseline := buildDummyInputShield(t, 125)
	assert.SolvingSucceeded(circuit, asCustomZoneEddsaOnly(baseline), test.WithCurves(ecc.BN254))

	assignment := buildDummyInputShield(t, 125)
	assignment.Inputs[0].SpendPublic = spendPublicVar(spptest.MustSpendPublic(t, spptest.Fe(777)))
	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// The address slot is pinned the same way: its owner hash and nullifier must
// stay derivable from (owner, seed) alone, which a slot-chosen key would break.
func TestAddressInputRejectsNonNeutralSpendKey(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(protocol.Shape{NInputs: 1, NOutputs: 2}))

	baseline, _, _ := buildZoneAddressAssignment(t)
	assert.SolvingSucceeded(circuit, asCustomZoneEddsaOnly(baseline), test.WithCurves(ecc.BN254))

	assignment, _, _ := buildZoneAddressAssignment(t)
	assignment.Inputs[0].SpendPublic = spendPublicVar(spptest.MustSpendPublic(t, spptest.Fe(777)))
	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
