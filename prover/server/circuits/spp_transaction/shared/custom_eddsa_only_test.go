package shared_test

import (
	"testing"

	customzone "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func MustNewCustomZoneEddsaOnlyCircuit(shape Shape) *customzone.CustomZoneEddsaOnlyCircuit {
	circuit, err := customzone.NewCustomZoneEddsaOnlyCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

// The Solana-only custom-zone circuit (no P256 gadget) proves a Solana-owned
// transaction. P256MessageHash must be 0 on this rail (no signature).
func TestCustomZoneEddsaOnlySolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		asCustomZoneEddsaOnly(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

// Soundness guard: the Solana-only variant must reject a P256-owned input
// (input_owner_pk_hashes[i] == 0 on a real slot), since it skips the
// signature gadget. Otherwise a UTXO owned by OwnerHash(0, nullifier_pk)
// could be spent with no signature.
func TestCustomZoneEddsaOnlyRejectsP256Input(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
