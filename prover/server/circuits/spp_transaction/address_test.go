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

// An address slot is a dummy input whose program_data_hash (the seed) is set. It
// does not spend a prior commitment; its nullifier is a program-owned address
// derived as Poseidon(utxoHash, 0, 0) with owner = program_id and every non-seed
// field pinned, so the address is f(program_id, seed) exactly.

func addressNullifier(t testing.TB, fields UtxoCircuitFields) *big.Int {
	t.Helper()
	utxoHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(fields))
	return spptest.MustNullifier(t, utxoHash, big.NewInt(0), big.NewInt(0))
}

// makeAddressSlot rewrites input idx into a valid address slot owned by
// programID with the given seed. Callers must finalize the assignment afterwards.
func makeAddressSlot(t testing.TB, assignment *Circuit, idx int, programID, seed *big.Int) {
	t.Helper()
	in := &assignment.Inputs[idx]
	in.IsDummy = spptest.Fe(1)
	in.Utxo.Domain = spptest.Fe(protocol.UtxoDomain)
	in.Utxo.Owner = programID
	in.Utxo.Asset = spptest.Fe(0)
	in.Utxo.Amount = spptest.Fe(0)
	in.Utxo.Blinding = spptest.Fe(0)
	in.Utxo.DataHash = seed
	in.Utxo.ProgramID = spptest.Fe(0)
	in.Utxo.ZoneDataHash = spptest.Fe(0)
	in.Utxo.ZoneProgramID = spptest.Fe(0)
	in.NullifierSecret = spptest.Fe(0)
	in.Nullifier = addressNullifier(t, in.Utxo)
	assignment.ProgramID = programID
}

// finalizeAddressAssignment recomputes the private-tx-hash (dummy/address inputs
// and dummy outputs contribute 0) and the public-input hash so a mutated witness
// stays internally consistent -- a negative test then fails on exactly one
// in-circuit constraint, not on a stale public hash.
func finalizeAddressAssignment(t testing.TB, assignment *Circuit, requiresP256, confidential bool) {
	t.Helper()
	inputHashes := make([]*big.Int, len(assignment.Inputs))
	addressHashes := make([]*big.Int, len(assignment.Inputs))
	for i := range assignment.Inputs {
		in := assignment.Inputs[i]
		isDummy := spptest.AsBigInt(in.IsDummy).Sign() != 0
		isAddress := isDummy && spptest.AsBigInt(in.Utxo.DataHash).Sign() != 0
		utxoHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(in.Utxo))
		if isDummy {
			inputHashes[i] = big.NewInt(0)
		} else {
			inputHashes[i] = utxoHash
		}
		if isAddress {
			addressHashes[i] = utxoHash
		} else {
			addressHashes[i] = big.NewInt(0)
		}
	}
	outputHashes := make([]*big.Int, len(assignment.Outputs))
	for i := range assignment.Outputs {
		if spptest.AsBigInt(assignment.Outputs[i].IsDummy).Sign() != 0 {
			outputHashes[i] = big.NewInt(0)
			continue
		}
		outputHashes[i] = spptest.AsBigInt(assignment.Outputs[i].Hash)
	}
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		inputHashes,
		outputHashes,
		addressHashes,
		spptest.AsBigInt(assignment.ExternalDataHash),
	)
	assignment.PrivateTxHash = privateTxHash
	if requiresP256 {
		assignment.P256MessageHashLow, assignment.P256MessageHashHigh = spptest.MustP256MessageLimbs(t, privateTxHash)
	} else {
		assignment.P256MessageHashLow = spptest.Fe(0)
		assignment.P256MessageHashHigh = spptest.Fe(0)
	}
	refreshPublicInputHashVariant(t, assignment, confidential, false)
}

// addressProgramID is a stand-in for solana_pk_hash(invoking_program); on-chain
// it is the authenticated CPI caller, here any non-zero field element.
func addressProgramID(t testing.TB) *big.Int {
	return testSolanaPkFieldSeed(t, 0x55)
}

// buildZoneAddressAssignment is the zone-variant positive baseline: a 1-in/2-out
// transaction whose single input is an address slot and whose outputs are empty,
// so it carries no value (0 = 0).
func buildZoneAddressAssignment(t testing.TB) (*Circuit, *big.Int, *big.Int) {
	t.Helper()
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(0))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(0))),
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
	programID := addressProgramID(t)
	seed := spptest.Fe(0xABCDEF)
	makeAddressSlot(t, assignment, 0, programID, seed)
	finalizeAddressAssignment(t, assignment, true, false)
	return assignment, programID, seed
}

// TestAddressSlotZoneSolves is the zone-variant positive baseline.
func TestAddressSlotZoneSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment, _, _ := buildZoneAddressAssignment(t)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestAddressSlotConfidentialSolves is the non-zone (confidential) positive
// baseline: the address logic lives in the shared constrainInput, so it must hold
// in both variants.
func TestAddressSlotConfidentialSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAsset := protocol.SolAsset()
	circuit := MustNewSolanaConfidentialCircuit(Shape(shape))

	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(0))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(0))),
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
	assignment.Confidential = true
	assignment.P256SigningPkField = spptest.Fe(0)
	pkField, nullifierPk := defaultOutputOwnerTag(t)
	for i := range assignment.Outputs {
		assignment.Outputs[i].OwnerPkHash = pkField
		assignment.Outputs[i].NullifierPk = nullifierPk
	}
	makeAddressSlot(t, assignment, 0, addressProgramID(t), spptest.Fe(0xABCDEF))
	finalizeAddressAssignment(t, assignment, false, true)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestAddressSlotRejectsWrongOwner pins owner == program_id: an address owned by
// anything other than the public program_id (with a nullifier recomputed to match
// so only the owner binding fails) is rejected. This is the program-exclusivity
// constraint.
func TestAddressSlotRejectsWrongOwner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment, _, _ := buildZoneAddressAssignment(t)

	assignment.Inputs[0].Utxo.Owner = testSolanaPkFieldSeed(t, 0x77)
	assignment.Inputs[0].Nullifier = addressNullifier(t, assignment.Inputs[0].Utxo)
	finalizeAddressAssignment(t, assignment, true, false)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestAddressSlotRejectsZeroProgramID pins program_id != 0: a direct user call
// leaves program_id at 0 and cannot mint an address (owner == program_id holds at
// 0 == 0, isolating the program_id-set constraint).
func TestAddressSlotRejectsZeroProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment, _, _ := buildZoneAddressAssignment(t)

	assignment.ProgramID = spptest.Fe(0)
	assignment.Inputs[0].Utxo.Owner = spptest.Fe(0)
	assignment.Inputs[0].Nullifier = addressNullifier(t, assignment.Inputs[0].Utxo)
	finalizeAddressAssignment(t, assignment, true, false)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestAddressSlotRejectsWrongNullifier pins the address derivation: the public
// nullifier must equal Poseidon(utxoHash, 0, 0).
func TestAddressSlotRejectsWrongNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment, _, _ := buildZoneAddressAssignment(t)

	assignment.Inputs[0].Nullifier = spptest.Fe(0xDEAD)
	finalizeAddressAssignment(t, assignment, true, false)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestAddressSlotRejectsUnpinnedField pins the PDA-determinism constraints: a
// non-zero value in any non-seed field (with the nullifier recomputed to match,
// so only the pin fails) breaks the f(program_id, seed) guarantee and is rejected.
func TestAddressSlotRejectsUnpinnedField(t *testing.T) {
	cases := []struct {
		name string
		set  func(in *Input)
	}{
		{"blinding", func(in *Input) { in.Utxo.Blinding = spptest.Fe(5) }},
		{"asset", func(in *Input) { in.Utxo.Asset = spptest.Fe(5) }},
		{"program_id_field", func(in *Input) { in.Utxo.ProgramID = spptest.Fe(5) }},
		{"zone_data_hash", func(in *Input) { in.Utxo.ZoneDataHash = spptest.Fe(5) }},
		{"zone_program_id", func(in *Input) { in.Utxo.ZoneProgramID = spptest.Fe(5) }},
		{"domain", func(in *Input) { in.Utxo.Domain = spptest.Fe(2) }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert := test.NewAssert(t)
			shape := protocol.Shape{NInputs: 1, NOutputs: 2}
			circuit := MustNewCircuit(Shape(shape))
			assignment, _, _ := buildZoneAddressAssignment(t)

			tc.set(&assignment.Inputs[0])
			assignment.Inputs[0].Nullifier = addressNullifier(t, assignment.Inputs[0].Utxo)
			finalizeAddressAssignment(t, assignment, true, false)

			assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
		})
	}
}

// TestAddressSlotRejectsNonZeroSecret pins nullifier_secret == 0: the address must
// not depend on a spender secret (recompute the nullifier with the non-zero secret
// so only the pin fails).
func TestAddressSlotRejectsNonZeroSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment, _, _ := buildZoneAddressAssignment(t)

	in := &assignment.Inputs[0]
	in.NullifierSecret = spptest.Fe(5)
	utxoHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(in.Utxo))
	in.Nullifier = spptest.MustNullifier(t, utxoHash, big.NewInt(0), big.NewInt(5))
	finalizeAddressAssignment(t, assignment, true, false)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestAddressSlotRejectsDuplicate pins distinctness: two address slots for the
// same (program_id, seed) derive the same address, so the in-transaction nullifier
// distinctness check rejects them.
func TestAddressSlotRejectsDuplicate(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	solAsset := protocol.SolAsset()
	circuit := MustNewCircuit(Shape(shape))

	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(0)),
			sampleUtxoWithAssetAndAmount(20, solAsset, spptest.Fe(0)),
		},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(0))),
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
	programID := addressProgramID(t)
	seed := spptest.Fe(0xABCDEF)
	makeAddressSlot(t, assignment, 0, programID, seed)
	makeAddressSlot(t, assignment, 1, programID, seed)
	finalizeAddressAssignment(t, assignment, true, false)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestPaddingDummyRejectsNonZeroOwner pins the padding convention: a padding dummy
// (no seed) must be owner 0.
func TestPaddingDummyRejectsNonZeroOwner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)

	assignment.Inputs[0].Utxo.Owner = testSolanaPkFieldSeed(t, 0x33)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
