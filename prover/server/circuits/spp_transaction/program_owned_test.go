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

// A program-owned value UTXO is a real input/output whose owner equals the public
// program_id (the authenticated CPI caller). It is authorized by the cpi_signer
// out of circuit: no user signature, no owner-hash binding, nullifier_secret 0. It
// may carry program data. User-owned slots may carry none.

// programOwnerID is a stand-in for solana_pk_hash(invoking_program); any non-zero
// field element distinct from the sample owner hashes.
func programOwnerID(t testing.TB) *big.Int {
	return testSolanaPkFieldSeed(t, 0x66)
}

// makeProgramOwnedInput rewrites input idx into a program-owned spend owned by
// programID, optionally carrying programData, then rebuilds the assignment so the
// state/nullifier proofs, private-tx hash, and public-input hash stay consistent.
func makeProgramOwnedInput(t testing.TB, assignment *Circuit, idx int, programID, programData *big.Int) {
	t.Helper()
	in := &assignment.Inputs[idx]
	in.Utxo.Owner = programID
	in.OwnerPkHash = programID
	in.NullifierSecret = spptest.Fe(0)
	in.Utxo.ProgramID = spptest.Fe(0)
	in.Utxo.DataHash = programData
	assignment.ProgramID = programID
	rebuildAfterOwnerChange(t, assignment)
}

// TestProgramOwnedInputSolves: a single program-owned input spends and verifies.
func TestProgramOwnedInputSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestProgramOwnedInputCarriesData: a program-owned input may carry program data.
func TestProgramOwnedInputCarriesData(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0xDA7A))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestProgramOwnedMixedInputs: one user input and one program-owned input in the
// same transaction.
func TestProgramOwnedMixedInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	// input 0 stays user-owned; input 1 becomes program-owned.
	makeProgramOwnedInput(t, assignment, 1, programOwnerID(t), spptest.Fe(0))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestProgramOwnedOutputSolves: an output owned by the program carries value and
// program data.
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
		ProgramID:     spptest.Fe(0),
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

// TestProgramOwnedRejectsNonZeroSecret pins nullifier_secret == 0 for a
// program-owned spend (the nullifier is recomputed to match, isolating the pin).
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

// TestProgramOwnedRejectsZeroProgramID: with program_id unset the slot is not
// program-owned, so it falls to the user path and the owner-hash binding fails --
// a program-owned UTXO cannot be spent without an authenticated program.
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

// TestProgramOwnedRejectsNonZeroProgramIDField pins the standalone program_id
// field to 0 on a real slot.
func TestProgramOwnedRejectsNonZeroProgramIDField(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0))

	assignment.Inputs[0].Utxo.ProgramID = spptest.Fe(5)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestUserInputRejectsProgramData: a user-owned spend may not carry program data.
func TestUserInputRejectsProgramData(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	assignment.Inputs[0].Utxo.DataHash = spptest.Fe(0xDA7A)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
