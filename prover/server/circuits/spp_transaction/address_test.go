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

func addressNullifier(t testing.TB, fields UtxoCircuitFields, nullifierSecret *big.Int) *big.Int {
	t.Helper()
	utxoHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(fields))
	return spptest.MustNullifier(t, utxoHash, big.NewInt(0), nullifierSecret)
}

func makeAddressSlot(t testing.TB, assignment *Circuit, idx int, ownerPkHash, seed *big.Int) {
	t.Helper()
	nullifierSecret := spptest.Fe(99)
	nullifierPk := spptest.MustNullifierPk(t, nullifierSecret)
	owner, err := protocol.OwnerHash(ownerPkHash, nullifierPk)
	if err != nil {
		t.Fatalf("address slot owner hash: %v", err)
	}
	in := &assignment.Inputs[idx]
	in.IsDummy = spptest.Fe(1)
	in.Utxo.Domain = spptest.Fe(protocol.UtxoDomain)
	in.Utxo.Owner = owner
	in.Utxo.Asset = spptest.Fe(0)
	in.Utxo.Amount = spptest.Fe(0)
	in.Utxo.Blinding = spptest.Fe(0)
	in.Utxo.DataHash = seed
	in.Utxo.ZoneDataHash = spptest.Fe(0)
	in.Utxo.ZoneProgramID = spptest.Fe(0)
	in.OwnerPkHash = ownerPkHash
	in.NullifierSecret = nullifierSecret
	in.Nullifier = addressNullifier(t, in.Utxo, nullifierSecret)
}

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

func addressOwnerPkHash(t testing.TB) *big.Int {
	return testSolanaPkFieldSeed(t, 0x55)
}

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
	ownerPkHash := addressOwnerPkHash(t)
	seed := spptest.Fe(0xABCDEF)
	makeAddressSlot(t, assignment, 0, ownerPkHash, seed)
	finalizeAddressAssignment(t, assignment, true, false)
	return assignment, ownerPkHash, seed
}

func TestAddressSlotZoneSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment, _, _ := buildZoneAddressAssignment(t)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

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
	makeAddressSlot(t, assignment, 0, addressOwnerPkHash(t), spptest.Fe(0xABCDEF))
	finalizeAddressAssignment(t, assignment, false, true)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestAddressSlotRejectsWrongOwner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment, _, _ := buildZoneAddressAssignment(t)

	assignment.Inputs[0].Utxo.Owner = testSolanaPkFieldSeed(t, 0x77)
	assignment.Inputs[0].Nullifier = addressNullifier(t, assignment.Inputs[0].Utxo, spptest.Fe(99))
	finalizeAddressAssignment(t, assignment, true, false)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestAddressSlotRejectsWrongNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment, _, _ := buildZoneAddressAssignment(t)

	assignment.Inputs[0].Nullifier = spptest.Fe(0xDEAD)
	finalizeAddressAssignment(t, assignment, true, false)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestAddressSlotRejectsUnpinnedField(t *testing.T) {
	cases := []struct {
		name string
		set  func(in *Input)
	}{
		{"blinding", func(in *Input) { in.Utxo.Blinding = spptest.Fe(5) }},
		{"asset", func(in *Input) { in.Utxo.Asset = spptest.Fe(5) }},
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
			assignment.Inputs[0].Nullifier = addressNullifier(t, assignment.Inputs[0].Utxo, spptest.Fe(99))
			finalizeAddressAssignment(t, assignment, true, false)

			assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
		})
	}
}

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
	ownerPkHash := addressOwnerPkHash(t)
	seed := spptest.Fe(0xABCDEF)
	makeAddressSlot(t, assignment, 0, ownerPkHash, seed)
	makeAddressSlot(t, assignment, 1, ownerPkHash, seed)
	finalizeAddressAssignment(t, assignment, true, false)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestPaddingDummyRejectsNonZeroOwner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildDummyInputShield(t, 125)

	assignment.Inputs[0].Utxo.Owner = testSolanaPkFieldSeed(t, 0x33)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
