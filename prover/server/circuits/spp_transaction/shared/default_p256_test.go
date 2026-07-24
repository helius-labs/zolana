package shared_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	defaultzone "zolana/prover/circuits/spp_transaction/default"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func MustNewDefaultZoneP256Circuit(shape Shape) *defaultzone.DefaultZoneP256Circuit {
	circuit, err := defaultzone.NewDefaultZoneP256Circuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

func mustP256PkField(t testing.TB, priv *ecdsa.PrivateKey) *big.Int {
	t.Helper()
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	// Owner pk_field is parity-free (matches OwnerPkFieldGadget); the viewing key
	// keeps the parity-folding P256PkField.
	pkField, err := protocol.OwnerPkField(compressed)
	if err != nil {
		t.Fatalf("p256 pk field: %v", err)
	}
	return pkField
}

// The P256 default-zone rail exposes the P256 input owner: input_owner_pk_hashes
// carries the real pk_field, equal to the shared p256_signing_pk_field, and the
// ownership path is selected by that equality.
func TestDefaultZoneP256ExposesInputOwner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	pkField := mustP256PkField(t, priv)
	assignment.Inputs[0].OwnerPkHash = pkField
	makeDefaultZone(t, assignment, pkField)

	assert.SolvingSucceeded(circuit, asDefaultZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// The P256 default-zone rail proves end to end (groth16), matching the Solana
// rail's TestDefaultZoneEddsaOnlySolves and the anonymous P256 prove coverage.
func TestDefaultZoneP256Solves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	pkField := mustP256PkField(t, priv)
	assignment.Inputs[0].OwnerPkHash = pkField
	makeDefaultZone(t, assignment, pkField)

	assert.SolvingSucceeded(circuit, asDefaultZoneP256(assignment), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		asDefaultZoneP256(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

// p256_signing_pk_field must equal the witnessed P256 key: a mismatch routes the
// input off the P256 path and fails the shared-key assertion.
func TestDefaultZoneP256RejectsWrongSigningPkField(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewDefaultZoneP256Circuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	pkField := mustP256PkField(t, priv)
	assignment.Inputs[0].OwnerPkHash = pkField
	makeDefaultZone(t, assignment, spptest.Fe(424242))

	assert.SolvingFailed(circuit, asDefaultZoneP256(assignment), test.WithCurves(ecc.BN254))
}
