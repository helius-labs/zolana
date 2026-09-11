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

// The record and its successor ride the sender's own transact, the PDA signs as one more owner.
func TestCustomRingEddsaOnlyCarriesANamespaceOwnedRecordSlot(t *testing.T) {
	for _, tc := range []struct {
		name       string
		recordRing *big.Int
	}{
		{"record in the default ring", big.NewInt(0)},
		{"record inside the ring", spptest.Fe(0x5A)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert := test.NewAssert(t)
			shape := protocol.Shape{NInputs: 2, NOutputs: 2}
			assignment := recordAssignment(t, shape, tc.recordRing)
			circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
			assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
		})
	}
}

func TestCustomRingEddsaOnlyRefusesAnUnsignedRecordSlot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	assignment := recordAssignment(t, shape, big.NewInt(0))
	for i := range assignment.SignerPkHashes {
		if spptest.AsBigInt(assignment.SignerPkHashes[i]).Cmp(recordNamespace(t)) == 0 {
			assignment.SignerPkHashes[i] = 0
		}
	}
	refreshPublicInputHash(t, assignment)
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

func recordNamespace(t testing.TB) *big.Int {
	return testSolanaPkFieldSeed(t, 0x77)
}

// Slot 0 is the sender's money, slot 1 the record and its successor.
func recordAssignment(t testing.TB, shape protocol.Shape, recordRing *big.Int) *testAssignment {
	t.Helper()
	ring := spptest.Fe(0x5A)
	sol := protocol.SolAsset()
	inputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(10, sol, spptest.Fe(100)),
		sampleUtxoWithAssetAndAmount(20, sol, spptest.Fe(0)),
	}
	outputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(100, sol, spptest.Fe(100)),
		sampleUtxoWithAssetAndAmount(110, sol, spptest.Fe(0)),
	}
	inputs[0].RingProgramID = ring
	outputs[0].RingProgramID = ring
	inputs[1].RingProgramID = recordRing
	outputs[1].RingProgramID = recordRing
	inputs[1].DataHash = spptest.Fe(0xd0c)
	outputs[1].DataHash = spptest.Fe(0xd1c)
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)
	assignment.RingProgramID = ring

	rewriteInputAsSolanaOwner(t, assignment, 1, 0x77, big.NewInt(0))
	namespace := recordNamespace(t)
	nullifierPk := spptest.MustNullifierPk(t, big.NewInt(0))
	owner, err := protocol.OwnerHash(namespace, nullifierPk)
	if err != nil {
		t.Fatalf("owner hash: %v", err)
	}
	assignment.Outputs[1].Utxo.Owner = owner
	assignment.Outputs[1].OwnerPkHash = namespace
	assignment.Outputs[1].NullifierPk = nullifierPk
	rebuildAfterOwnerChange(t, assignment)
	return assignment
}
