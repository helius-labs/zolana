package shared_test

import (
	"math/big"
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

// The Solana-only custom-zone circuit proves a Solana-owned transaction.
func TestCustomZoneEddsaOnlySolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
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

// Soundness guard: the Solana-only variant must reject a content slot whose
// public owner tag is the 0 sentinel (the dropped P256 rail's routing mark),
// since it has no signature gadget to authorize it. Otherwise a UTXO owned by
// OwnerHash(0, nullifier_pk) could be spent with no signature.
func TestCustomZoneEddsaOnlyRejectsZeroOwnerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	owner, err := protocol.OwnerHash(big.NewInt(0), assignment.Inputs[0].SpendKey.Public)
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Inputs[0].Utxo.Owner = owner
	assignment.Inputs[0].OwnerPkHash = spptest.Fe(0)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, asCustomZoneEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
