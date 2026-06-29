package transaction_test

import (
	"math/big"
	"testing"
	. "zolana/prover/circuits/spp_transaction"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func programOwnerID(t testing.TB) *big.Int {
	return testSolanaPkFieldSeed(t, 0x66)
}

func makeProgramOwnedInput(t testing.TB, assignment *Circuit, idx int, programID, programData *big.Int) {
	t.Helper()
	in := &assignment.Inputs[idx]
	in.Utxo.Owner = programID
	in.OwnerPkHash = programID
	in.NullifierSecret = spptest.Fe(0)
	in.Utxo.DataHash = programData
	assignment.ProgramID = programID
	rebuildAfterOwnerChange(t, assignment)
}

func TestProgramOwnedInputSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestProgramOwnedInputCarriesData(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0xDA7A))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestProgramOwnedMixedInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 1, programOwnerID(t), spptest.Fe(0))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestProgramOwnedOutputSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 1}
	solAsset := protocol.SolAsset()
	circuit := MustNewCircuit(Shape(shape))
	programID := programOwnerID(t)

	output := protocol.Utxo{
		Domain:        spptest.Fe(protocol.UtxoDomain),
		Owner:         programID,
		Asset:         solAsset,
		Amount:        spptest.Fe(100),
		Blinding:      spptest.Fe(5),
		DataHash:      spptest.Fe(0xDA7A),
		ZoneDataHash:  spptest.Fe(0),
		ZoneProgramID: spptest.Fe(0),
	}
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
		[]protocol.Utxo{output},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
	assignment.ProgramID = programID
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestProgramOwnedRejectsNonZeroSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0))

	assignment.Inputs[0].NullifierSecret = spptest.Fe(5)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestProgramOwnedRejectsZeroProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0))

	assignment.ProgramID = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestUserInputRejectsProgramData(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	assignment.Inputs[0].Utxo.DataHash = spptest.Fe(0xDA7A)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
