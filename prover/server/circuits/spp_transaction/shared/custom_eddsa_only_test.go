package shared_test

import (
	"math/big"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func MustNewCustomRingEddsaOnlyCircuit(shape Shape) *customring.CustomRingEddsaOnlyCircuit {
	circuit, err := customring.NewCustomRingEddsaOnlyCircuit(shape)
	if err != nil {
		panic(err)
	}
	return circuit
}

// The Solana-only custom-ring circuit proves a Solana-owned transaction.
func TestCustomRingEddsaOnlySolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		asCustomRingEddsaOnly(assignment),
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

func TestCustomRingEddsaOnlyPublicInputHashBindsEveryField(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	refreshHash := func() { refreshPublicInputHash(t, assignment) }
	refreshHash()

	assertPublicInputHashBindsEveryField(
		t,
		circuit,
		assignment,
		func() frontend.Circuit { return asCustomRingEddsaOnly(assignment) },
		refreshHash,
		publicInputHashBindingOptions{
			includeRingProgramID:       true,
			includeOutputOwnerPkHashes: true,
			signerWidth:                len(assignment.SignerPkHashes),
		},
	)
}

// Soundness guard: the Solana-only variant must reject a content slot whose
// public owner tag is the 0 sentinel (the dropped P256 rail's routing mark),
// since it has no signature gadget to authorize it. Otherwise a UTXO owned by
// OwnerHash(0, nullifier_pk) could be spent with no signature.
func TestCustomRingEddsaOnlyRejectsZeroOwnerTag(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	nullifierSecret := spptest.AsBigInt(assignment.Inputs[0].NullifierSecret)
	nullifierPk := spptest.MustNullifierPk(t, nullifierSecret)
	owner, err := protocol.OwnerHash(big.NewInt(0), nullifierPk)
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Inputs[0].Utxo.Owner = owner
	assignment.Inputs[0].OwnerPkHash = spptest.Fe(0)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
