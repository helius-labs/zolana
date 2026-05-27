package spp

import (
	"crypto/ed25519"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestCircuitSkeletonCompilesForSupportedShapes(t *testing.T) {
	for _, shape := range SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			circuit := MustNewCircuit(shape)
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300)); err != nil {
				t.Fatalf("compile SPP circuit %s: %v", shape, err)
			}
		})
	}
}

func TestCircuitSkeletonProvesForSupportedShapes(t *testing.T) {
	for _, shape := range SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := MustNewCircuit(shape)
			assignment := buildCircuitAssignment(t, shape)

			assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
			assert.ProverSucceeded(
				circuit,
				assignment,
				test.WithBackends(backend.GROTH16),
				test.WithCurves(ecc.BN254),
				test.NoSerializationChecks(),
			)
		})
	}
}

func TestCircuitSkeletonRejectsBadOutputHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.OutputUtxoHashes[0] = fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadStatePath(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.StatePath[0][0] = fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadStateDirection(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	if asBigInt(assignment.StatePathDirs[0][0]).Sign() == 0 {
		assignment.StatePathDirs[0][0] = fe(1)
	} else {
		assignment.StatePathDirs[0][0] = fe(0)
	}

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadNullifierNonInclusionPath(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.NfLowPath[0][0] = fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadNullifierRange(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.NfLowValue[0] = assignment.Nullifiers[0]

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadPreNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.PreNullifiers[0] = fe(998)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsSolanaSignerOwnerMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.SolanaPubkeyHash = fe(12345)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsExternalDataHashMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.ExternalDataHash = fe(301)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBalanceMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := fe(7)
	inputs := []Utxo{
		sampleUtxoWithAssetAndAmount(10, assetID, fe(100)),
	}
	outputs := []Utxo{
		sampleUtxoWithAssetAndAmount(100, assetID, fe(40)),
		sampleUtxoWithAssetAndAmount(110, assetID, fe(70)),
	}
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		inputs,
		outputs,
		big.NewInt(0),
		big.NewInt(0),
		fe(0),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonAcceptsPublicSolMovement(t *testing.T) {
	shape := Shape{NInputs: 1, NOutputs: 1}
	solAssetID := fe(SpecSolAssetID)

	t.Run("deposit", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewCircuit(shape)
		assignment := buildCircuitAssignmentFromUtxos(
			t,
			shape,
			[]Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, fe(100))},
			[]Utxo{sampleUtxoWithAssetAndAmount(100, solAssetID, fe(125))},
			big.NewInt(25),
			big.NewInt(0),
			fe(0),
		)

		assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	})

	t.Run("withdraw", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewCircuit(shape)
		assignment := buildCircuitAssignmentFromUtxos(
			t,
			shape,
			[]Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, fe(100))},
			[]Utxo{sampleUtxoWithAssetAndAmount(100, solAssetID, fe(75))},
			big.NewInt(-25),
			big.NewInt(0),
			fe(0),
		)

		assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	})
}

func TestCircuitSkeletonAcceptsPublicSplDeposit(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	publicSplAssetPubkey := fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, publicSplAssetPubkey, fe(100))},
		[]Utxo{sampleUtxoWithAssetAndAmount(100, publicSplAssetPubkey, fe(125))},
		big.NewInt(0),
		big.NewInt(25),
		publicSplAssetPubkey,
	)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsPublicSplAssetMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	privateAssetID := fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, privateAssetID, fe(100))},
		[]Utxo{sampleUtxoWithAssetAndAmount(100, privateAssetID, fe(125))},
		big.NewInt(0),
		big.NewInt(25),
		fe(88),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsPublicSplMovementOnSolAsset(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	solAssetID := fe(SpecSolAssetID)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, fe(100))},
		[]Utxo{sampleUtxoWithAssetAndAmount(100, solAssetID, fe(125))},
		big.NewInt(0),
		big.NewInt(25),
		solAssetID,
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsPhantomPublicSplMovement(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	privateAssetID := fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, privateAssetID, fe(100))},
		[]Utxo{sampleUtxoWithAssetAndAmount(100, privateAssetID, fe(100))},
		big.NewInt(0),
		big.NewInt(25),
		fe(88),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonAcceptsDummyInputForPublicDeposit(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	publicSplAssetPubkey := fe(77)
	assignment := buildCircuitAssignmentWithDummies(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, publicSplAssetPubkey, fe(0))},
		[]Utxo{sampleUtxoWithAssetAndAmount(100, publicSplAssetPubkey, fe(25))},
		[]bool{true},
		[]bool{false},
		big.NewInt(0),
		big.NewInt(25),
		publicSplAssetPubkey,
	)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonAcceptsDummyOutput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := fe(77)
	assignment := buildCircuitAssignmentWithDummies(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, assetID, fe(100))},
		[]Utxo{
			sampleUtxoWithAssetAndAmount(100, assetID, fe(100)),
			sampleUtxoWithAssetAndAmount(110, assetID, fe(0)),
		},
		[]bool{false},
		[]bool{false, true},
		big.NewInt(0),
		big.NewInt(0),
		fe(0),
	)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsDummyInputWithValue(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	publicSplAssetPubkey := fe(77)
	assignment := buildCircuitAssignmentWithDummies(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, publicSplAssetPubkey, fe(5))},
		[]Utxo{sampleUtxoWithAssetAndAmount(100, publicSplAssetPubkey, fe(25))},
		[]bool{true},
		[]bool{false},
		big.NewInt(0),
		big.NewInt(25),
		publicSplAssetPubkey,
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonIgnoresDummyInputStatePath(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	publicSplAssetPubkey := fe(77)
	assignment := buildCircuitAssignmentWithDummies(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, publicSplAssetPubkey, fe(0))},
		[]Utxo{sampleUtxoWithAssetAndAmount(100, publicSplAssetPubkey, fe(25))},
		[]bool{true},
		[]bool{false},
		big.NewInt(0),
		big.NewInt(25),
		publicSplAssetPubkey,
	)
	assignment.StatePath[0][0] = fe(999)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonIgnoresDummyInputNullifierPath(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 1}
	circuit := MustNewCircuit(shape)
	publicSplAssetPubkey := fe(77)
	assignment := buildCircuitAssignmentWithDummies(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, publicSplAssetPubkey, fe(0))},
		[]Utxo{sampleUtxoWithAssetAndAmount(100, publicSplAssetPubkey, fe(25))},
		[]bool{true},
		[]bool{false},
		big.NewInt(0),
		big.NewInt(25),
		publicSplAssetPubkey,
	)
	assignment.NfLowPath[0][0] = fe(999)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsDummyOutputWithPublicHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := fe(77)
	assignment := buildCircuitAssignmentWithDummies(
		t,
		shape,
		[]Utxo{sampleUtxoWithAssetAndAmount(10, assetID, fe(100))},
		[]Utxo{
			sampleUtxoWithAssetAndAmount(100, assetID, fe(100)),
			sampleUtxoWithAssetAndAmount(110, assetID, fe(0)),
		},
		[]bool{false},
		[]bool{false, true},
		big.NewInt(0),
		big.NewInt(0),
		fe(0),
	)
	assignment.OutputUtxoHashes[1] = fe(999)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func buildCircuitAssignment(t *testing.T, shape Shape) *Circuit {
	t.Helper()

	inputUtxos, outputUtxos := defaultBalancedUtxos(t, shape)
	return buildCircuitAssignmentFromUtxos(
		t,
		shape,
		inputUtxos,
		outputUtxos,
		big.NewInt(0),
		big.NewInt(0),
		fe(0),
	)
}

func buildCircuitAssignmentFromUtxos(
	t *testing.T,
	shape Shape,
	inputUtxos []Utxo,
	outputUtxos []Utxo,
	publicSolAmount *big.Int,
	publicSplAmount *big.Int,
	publicSplAssetPubkey *big.Int,
) *Circuit {
	t.Helper()
	return buildCircuitAssignmentWithDummies(
		t,
		shape,
		inputUtxos,
		outputUtxos,
		make([]bool, shape.NInputs),
		make([]bool, shape.NOutputs),
		publicSolAmount,
		publicSplAmount,
		publicSplAssetPubkey,
	)
}

func buildCircuitAssignmentWithDummies(
	t *testing.T,
	shape Shape,
	inputUtxos []Utxo,
	outputUtxos []Utxo,
	isDummyInput []bool,
	isDummyOutput []bool,
	publicSolAmount *big.Int,
	publicSplAmount *big.Int,
	publicSplAssetPubkey *big.Int,
) *Circuit {
	t.Helper()
	if len(inputUtxos) != shape.NInputs {
		t.Fatalf("input UTXO count mismatch: got %d want %d", len(inputUtxos), shape.NInputs)
	}
	if len(outputUtxos) != shape.NOutputs {
		t.Fatalf("output UTXO count mismatch: got %d want %d", len(outputUtxos), shape.NOutputs)
	}
	if len(isDummyInput) != shape.NInputs {
		t.Fatalf("dummy input count mismatch: got %d want %d", len(isDummyInput), shape.NInputs)
	}
	if len(isDummyOutput) != shape.NOutputs {
		t.Fatalf("dummy output count mismatch: got %d want %d", len(isDummyOutput), shape.NOutputs)
	}

	nullifierSecret := fe(99)
	inputCircuitUtxos := make([]UtxoCircuitFields, shape.NInputs)
	inputHashes := make([]*big.Int, shape.NInputs)
	preNullifiers := make([]frontend.Variable, shape.NInputs)
	nullifiers := make([]frontend.Variable, shape.NInputs)
	dummyInputVars := make([]frontend.Variable, shape.NInputs)
	stateEntries := make(map[uint64]*big.Int)
	stateLeafIndices := make([]uint64, shape.NInputs)

	for i := 0; i < shape.NInputs; i++ {
		utxo := inputUtxos[i]
		inputCircuitUtxos[i] = toCircuitFields(utxo)
		inputHash := maybeDummyHash(t, mustUtxoHash(t, utxo), isDummyInput[i])
		inputHashes[i] = inputHash
		preNullifier := maybeDummyHash(t, mustPreNullifier(t, utxo.Blinding, nullifierSecret), isDummyInput[i])
		preNullifiers[i] = preNullifier
		nullifiers[i] = maybeDummyHash(t, mustNullifierHash(t, inputHash, preNullifier), isDummyInput[i])
		dummyInputVars[i] = boolVar(isDummyInput[i])
		stateLeafIndices[i] = defaultStateLeafIndex(i)
		if !isDummyInput[i] {
			stateEntries[stateLeafIndices[i]] = inputHash
		}
	}
	stateRoot, stateProofs := BuildSparseStateTree(stateEntries)
	statePathVars := make([][]frontend.Variable, shape.NInputs)
	stateDirVars := make([][]frontend.Variable, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		statePathVars[i] = make([]frontend.Variable, StateTreeHeight)
		stateDirVars[i] = make([]frontend.Variable, StateTreeHeight)
		for j := 0; j < StateTreeHeight; j++ {
			statePathVars[i][j] = fe(0)
			stateDirVars[i][j] = fe(0)
		}
		if isDummyInput[i] {
			continue
		}
		proof := stateProofs[stateLeafIndices[i]]
		fillStateProofVariables(statePathVars[i], stateDirVars[i], proof)
	}

	nullifierTree := NewIndexedTree()
	nfLowValueVars := make([]frontend.Variable, shape.NInputs)
	nfNextValueVars := make([]frontend.Variable, shape.NInputs)
	nfLowPathVars := make([][]frontend.Variable, shape.NInputs)
	nfLowDirVars := make([][]frontend.Variable, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		nfLowValueVars[i] = fe(0)
		nfNextValueVars[i] = fe(0)
		nfLowPathVars[i] = make([]frontend.Variable, NullifierTreeHeight)
		nfLowDirVars[i] = make([]frontend.Variable, NullifierTreeHeight)
		for j := 0; j < NullifierTreeHeight; j++ {
			nfLowPathVars[i][j] = fe(0)
			nfLowDirVars[i][j] = fe(0)
		}
		if isDummyInput[i] {
			continue
		}
		witness := nullifierTree.NonInclusion(asBigInt(nullifiers[i]))
		nfLowValueVars[i] = witness.LowValue
		nfNextValueVars[i] = witness.NextValue
		fillStateProofVariables(nfLowPathVars[i], nfLowDirVars[i], StateTreeWitness{
			Siblings:   witness.Siblings,
			Directions: witness.Directions,
		})
	}
	utxoTreeRoots := repeatBigInt(stateRoot, shape.NInputs)
	nullifierRoots := repeatBigInt(nullifierTree.Root, shape.NInputs)

	outputCircuitUtxos := make([]UtxoCircuitFields, shape.NOutputs)
	outputHashes := make([]*big.Int, shape.NOutputs)
	outputHashVariables := make([]frontend.Variable, shape.NOutputs)
	dummyOutputVars := make([]frontend.Variable, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		utxo := outputUtxos[i]
		outputCircuitUtxos[i] = toCircuitFields(utxo)
		outputHash := maybeDummyHash(t, mustUtxoHash(t, utxo), isDummyOutput[i])
		outputHashes[i] = outputHash
		outputHashVariables[i] = outputHash
		dummyOutputVars[i] = boolVar(isDummyOutput[i])
	}

	externalDataHash := fe(300)
	expiry := fe(400)
	privateTxHash := mustPrivateTxHash(t, inputHashes, outputHashes, externalDataHash, expiry)
	solanaPubkeyHash := firstRealInputOwner(inputUtxos, isDummyInput)

	publicInputs := PublicInputs{
		Nullifiers:           toBigInts(nullifiers),
		OutputUtxoHashes:     outputHashes,
		UtxoTreeRoots:        utxoTreeRoots,
		NullifierRoots:       nullifierRoots,
		PrivateTxHash:        privateTxHash,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		PublicAmountMode:     fe(0),
		PublicSolAmount:      SignedToFe(publicSolAmount),
		PublicSplAmount:      SignedToFe(publicSplAmount),
		RelayerFee:           fe(0),
		PublicSplAssetPubkey: publicSplAssetPubkey,
		ProgramIDHashchain:   fe(0),
		SolanaPubkeyHash:     solanaPubkeyHash,
		DataHash:             fe(0),
		PolicyData:           fe(0),
	}
	publicInputHashValue, err := PublicInputHash(publicInputs)
	publicInputHash := mustHash(t, publicInputHashValue, err)

	return &Circuit{
		Shape:                shape,
		InputUtxos:           inputCircuitUtxos,
		PreNullifiers:        preNullifiers,
		IsDummyInput:         dummyInputVars,
		StatePath:            statePathVars,
		StatePathDirs:        stateDirVars,
		NfLowValue:           nfLowValueVars,
		NfNextValue:          nfNextValueVars,
		NfLowPath:            nfLowPathVars,
		NfLowPathDirs:        nfLowDirVars,
		UtxoTreeRoots:        toFrontendVariables(utxoTreeRoots),
		NullifierRoots:       toFrontendVariables(nullifierRoots),
		OutputUtxos:          outputCircuitUtxos,
		IsDummyOutput:        dummyOutputVars,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		PublicAmountMode:     publicInputs.PublicAmountMode,
		RelayerFee:           publicInputs.RelayerFee,
		Nullifiers:           nullifiers,
		OutputUtxoHashes:     outputHashVariables,
		PrivateTxHash:        privateTxHash,
		PublicSolAmount:      publicInputs.PublicSolAmount,
		PublicSplAmount:      publicInputs.PublicSplAmount,
		PublicSplAssetPubkey: publicInputs.PublicSplAssetPubkey,
		ProgramIDHashchain:   publicInputs.ProgramIDHashchain,
		SolanaPubkeyHash:     publicInputs.SolanaPubkeyHash,
		DataHash:             publicInputs.DataHash,
		PolicyData:           publicInputs.PolicyData,
		PublicInputHash:      publicInputHash,
	}
}

func boolVar(value bool) frontend.Variable {
	if value {
		return 1
	}
	return 0
}

func maybeDummyHash(_ *testing.T, value *big.Int, dummy bool) *big.Int {
	if dummy {
		return fe(0)
	}
	return value
}

func defaultStateLeafIndex(i int) uint64 {
	return uint64(17 + i)
}

func fillStateProofVariables(path []frontend.Variable, dirs []frontend.Variable, proof StateTreeWitness) {
	if len(path) != len(proof.Siblings) {
		panic("spp test: state path length mismatch")
	}
	if len(dirs) != len(proof.Directions) {
		panic("spp test: state direction length mismatch")
	}
	for i := range proof.Siblings {
		path[i] = proof.Siblings[i]
		dirs[i] = fe(int64(proof.Directions[i]))
	}
}

func refreshPublicInputHash(t *testing.T, assignment *Circuit) {
	t.Helper()
	publicInputs := PublicInputs{
		Nullifiers:           toBigInts(assignment.Nullifiers),
		OutputUtxoHashes:     toBigInts(assignment.OutputUtxoHashes),
		UtxoTreeRoots:        toBigInts(assignment.UtxoTreeRoots),
		NullifierRoots:       toBigInts(assignment.NullifierRoots),
		PrivateTxHash:        asBigInt(assignment.PrivateTxHash),
		ExternalDataHash:     asBigInt(assignment.ExternalDataHash),
		ExpiryUnixTs:         asBigInt(assignment.ExpiryUnixTs),
		PublicAmountMode:     asBigInt(assignment.PublicAmountMode),
		PublicSolAmount:      asBigInt(assignment.PublicSolAmount),
		PublicSplAmount:      asBigInt(assignment.PublicSplAmount),
		RelayerFee:           asBigInt(assignment.RelayerFee),
		PublicSplAssetPubkey: asBigInt(assignment.PublicSplAssetPubkey),
		ProgramIDHashchain:   asBigInt(assignment.ProgramIDHashchain),
		SolanaPubkeyHash:     asBigInt(assignment.SolanaPubkeyHash),
		DataHash:             asBigInt(assignment.DataHash),
		PolicyData:           asBigInt(assignment.PolicyData),
	}
	publicInputHashValue, err := PublicInputHash(publicInputs)
	assignment.PublicInputHash = mustHash(t, publicInputHashValue, err)
}

func defaultBalancedUtxos(t *testing.T, shape Shape) ([]Utxo, []Utxo) {
	t.Helper()

	assetID := fe(7)
	inputs := make([]Utxo, shape.NInputs)
	total := int64(0)
	for i := 0; i < shape.NInputs; i++ {
		amount := int64(100 + i*10)
		inputs[i] = sampleUtxoWithAssetAndAmount(10+i*10, assetID, fe(amount))
		total += amount
	}
	outputs := make([]Utxo, shape.NOutputs)
	remaining := total
	for i := 0; i < shape.NOutputs; i++ {
		amount := remaining / int64(shape.NOutputs-i)
		remaining -= amount
		outputs[i] = sampleUtxoWithAssetAndAmount(100+i*10, assetID, fe(amount))
	}
	return inputs, outputs
}

func sampleUtxoWithAssetAndAmount(base int, assetID, amount *big.Int) Utxo {
	utxo := sampleUtxo(base)
	utxo.AssetID = new(big.Int).Set(assetID)
	utxo.AssetAmount = new(big.Int).Set(amount)
	return utxo
}

func sampleUtxo(base int) Utxo {
	return Utxo{
		Domain:          fe(int64(base + 1)),
		Owner:           testSolanaSignerHash(),
		AssetID:         fe(int64(base + 3)),
		AssetAmount:     fe(int64(base + 4)),
		Blinding:        fe(int64(base + 5)),
		DataHash:        fe(int64(base + 6)),
		PolicyData:      fe(int64(base + 7)),
		PolicyProgramID: fe(int64(base + 8)),
	}
}

func testSolanaSignerHash() *big.Int {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	key := ed25519.NewKeyFromSeed(seed)
	return HashToFieldSize(key[32:])
}

func firstRealInputOwner(inputs []Utxo, isDummy []bool) *big.Int {
	for i, input := range inputs {
		if !isDummy[i] {
			return new(big.Int).Set(input.Owner)
		}
	}
	return fe(0)
}

func toCircuitFields(utxo Utxo) UtxoCircuitFields {
	return UtxoCircuitFields{
		Domain:          utxo.Domain,
		Owner:           utxo.Owner,
		AssetID:         utxo.AssetID,
		AssetAmount:     utxo.AssetAmount,
		Blinding:        utxo.Blinding,
		DataHash:        utxo.DataHash,
		PolicyData:      utxo.PolicyData,
		PolicyProgramID: utxo.PolicyProgramID,
	}
}

func toBigInts(values []frontend.Variable) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = asBigInt(value)
	}
	return out
}

func repeatBigInt(value *big.Int, count int) []*big.Int {
	out := make([]*big.Int, count)
	for i := range out {
		out[i] = new(big.Int).Set(value)
	}
	return out
}

func toFrontendVariables(values []*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func asBigInt(value frontend.Variable) *big.Int {
	switch v := value.(type) {
	case *big.Int:
		return v
	case int:
		return big.NewInt(int64(v))
	case int64:
		return big.NewInt(v)
	default:
		panic("spp test: unsupported frontend.Variable value type")
	}
}
