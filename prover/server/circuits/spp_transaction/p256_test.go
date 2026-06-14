package transaction_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"
	. "zolana/prover/circuits/spp_transaction"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestCircuitAcceptsP256Owner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadP256Signature(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	wrongSigner := spptest.FixedP256Key(t, 12)
	rewriteSingleInputAsP256(t, assignment, priv, wrongSigner)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadP256MessageHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.P256MessageHashLow = new(big.Int).Add(spptest.AsBigInt(assignment.P256MessageHashLow), big.NewInt(1))
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsP256PubkeyOwnerMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	ownerPriv := spptest.FixedP256Key(t, 11)
	signingPriv := spptest.FixedP256Key(t, 12)
	rewriteSingleInputAsP256(t, assignment, ownerPriv, signingPriv)
	assignment.P256Pub = spptest.P256PubkeyAssignment(signingPriv)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// p256PkFieldUnitCircuit wraps P256PkFieldFromPubkeyCircuit alone. The gnark
// ECDSA gadget assumes a valid public key and never checks it lies on the
// curve, so the AssertIsOnCurve here is the sole constraint rejecting an
// off-curve point. It cannot be exercised through the full circuit: the
// signature gadget's prover-side scalar-mul hint calls crypto/elliptic, which
// panics on an invalid point before solving reaches any constraint.
type p256PkFieldUnitCircuit struct {
	Pub     P256PublicKey
	PkField frontend.Variable `gnark:",public"`
}

func (c *p256PkFieldUnitCircuit) Define(api frontend.API) error {
	pkField, err := P256PkFieldFromPubkeyCircuit(api, c.Pub)
	if err != nil {
		return err
	}
	api.AssertIsEqual(pkField, c.PkField)
	return nil
}

// Positive control for the rejection test below: a valid key solves and the
// circuit pk_field matches the native protocol.P256PkField.
func TestP256PkFieldCircuitMatchesNative(t *testing.T) {
	assert := test.NewAssert(t)
	priv := spptest.FixedP256Key(t, 11)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	pkField, err := protocol.P256PkField(compressed)
	if err != nil {
		t.Fatalf("native P256 pk field: %v", err)
	}
	assignment := &p256PkFieldUnitCircuit{
		Pub:     spptest.P256PubkeyAssignment(priv),
		PkField: pkField,
	}

	assert.SolvingSucceeded(&p256PkFieldUnitCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

func TestP256PkFieldCircuitRejectsOffCurvePubkey(t *testing.T) {
	assert := test.NewAssert(t)
	// (1,1) is not on P256 (1 != 1 - 3 + b) and is not the (0,0) infinity
	// encoding AssertIsOnCurve admits. PkField carries the hash these
	// coordinates would produce (yIsOdd=1, xLow=1, xHigh=0), so the on-curve
	// check is the only constraint left to reject.
	xHash := spptest.MustPoseidon(t, 3, []*big.Int{spptest.Fe(1), spptest.Fe(0)})
	pkField := spptest.MustPoseidon(t, 3, []*big.Int{spptest.Fe(1), xHash})
	assignment := &p256PkFieldUnitCircuit{
		Pub: P256PublicKey{
			X: emulated.ValueOf[emulated.P256Fp](1),
			Y: emulated.ValueOf[emulated.P256Fp](1),
		},
		PkField: pkField,
	}

	assert.SolvingFailed(&p256PkFieldUnitCircuit{}, assignment, test.WithCurves(ecc.BN254))
}
