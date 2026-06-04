package transaction

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"light/light-prover/prover/spp/internal/p256key"
	"light/light-prover/prover/spp/model"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
)

func TestCircuitSkeletonCompilesForSupportedShapes(t *testing.T) {
	for _, shape := range model.SupportedShapes {
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
	for _, shape := range model.SupportedShapes {
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
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Outputs[0].Hash = fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadStatePath(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].StatePath[0] = fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadStateDirection(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	if asBigInt(assignment.Inputs[0].StatePathDirs[0]).Sign() == 0 {
		assignment.Inputs[0].StatePathDirs[0] = fe(1)
	} else {
		assignment.Inputs[0].StatePathDirs[0] = fe(0)
	}

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadNullifierNonInclusionPath(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].NfLowPath[0] = fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadNullifierRange(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].NfLowValue = assignment.Inputs[0].Nullifier

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadNullifierSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.NullifierSecret = fe(998)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsSolanaSignerOwnerMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].SolanaPkHash = fe(12345)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonAcceptsP256Owner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := mustFixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBadP256Signature(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := mustFixedP256Key(t, 11)
	wrongSigner := mustFixedP256Key(t, 12)
	rewriteSingleInputAsP256(t, assignment, priv, wrongSigner)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsP256PubkeyOwnerMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	ownerPriv := mustFixedP256Key(t, 11)
	signingPriv := mustFixedP256Key(t, 12)
	rewriteSingleInputAsP256(t, assignment, ownerPriv, signingPriv)
	assignment.P256Pub = p256PubkeyAssignment(signingPriv)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsOwnerHashPreimageMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].Utxo.Owner = fe(12345)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsExternalDataHashMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.ExternalDataHash = fe(301)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsBalanceMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := fe(7)
	inputs := []model.Utxo{
		sampleUtxoWithAssetAndAmount(10, assetID, fe(100)),
	}
	outputs := []model.Utxo{
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
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	solAssetID := fe(model.SpecSolAssetID)

	t.Run("deposit", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewCircuit(shape)
		assignment := buildCircuitAssignmentFromUtxos(
			t,
			shape,
			[]model.Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, fe(100))},
			twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAssetID, fe(125))),
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
			[]model.Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, fe(100))},
			twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAssetID, fe(75))),
			big.NewInt(-25),
			big.NewInt(0),
			fe(0),
		)

		assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	})
}

func TestCircuitSkeletonAcceptsPublicSplDeposit(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	publicSplAssetPubkey := fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]model.Utxo{sampleUtxoWithAssetAndAmount(10, publicSplAssetPubkey, fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, publicSplAssetPubkey, fe(125))),
		big.NewInt(0),
		big.NewInt(25),
		publicSplAssetPubkey,
	)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsPublicSplAssetMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	privateAssetID := fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]model.Utxo{sampleUtxoWithAssetAndAmount(10, privateAssetID, fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, privateAssetID, fe(125))),
		big.NewInt(0),
		big.NewInt(25),
		fe(88),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsPublicSplMovementOnSolAsset(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	solAssetID := fe(model.SpecSolAssetID)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]model.Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAssetID, fe(125))),
		big.NewInt(0),
		big.NewInt(25),
		solAssetID,
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitSkeletonRejectsPhantomPublicSplMovement(t *testing.T) {
	assert := test.NewAssert(t)
	shape := model.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	privateAssetID := fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]model.Utxo{sampleUtxoWithAssetAndAmount(10, privateAssetID, fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, privateAssetID, fe(100))),
		big.NewInt(0),
		big.NewInt(25),
		fe(88),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func buildCircuitAssignment(t *testing.T, shape model.Shape) *Circuit {
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
	shape model.Shape,
	inputUtxos []model.Utxo,
	outputUtxos []model.Utxo,
	publicSolAmount *big.Int,
	publicSplAmount *big.Int,
	publicSplAssetPubkey *big.Int,
) *Circuit {
	t.Helper()
	return buildCircuitAssignmentExact(
		t,
		shape,
		inputUtxos,
		outputUtxos,
		publicSolAmount,
		publicSplAmount,
		publicSplAssetPubkey,
	)
}

func buildCircuitAssignmentExact(
	t *testing.T,
	shape model.Shape,
	inputUtxos []model.Utxo,
	outputUtxos []model.Utxo,
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

	nullifierSecret := fe(99)
	inputOwnerKeyHashValue := testSolanaPkHash(t)
	inputCircuitUtxos := make([]UtxoCircuitFields, shape.NInputs)
	inputHashes := make([]*big.Int, shape.NInputs)
	solanaPkHashes := make([]frontend.Variable, shape.NInputs)
	nullifiers := make([]frontend.Variable, shape.NInputs)
	stateEntries := make(map[uint64]*big.Int)
	stateLeafIndices := make([]uint64, shape.NInputs)

	for i := 0; i < shape.NInputs; i++ {
		utxo := inputUtxos[i]
		inputCircuitUtxos[i] = toCircuitFields(utxo)
		inputHash := mustUtxoHash(t, utxo)
		inputHashes[i] = inputHash
		solanaPkHashes[i] = inputOwnerKeyHashValue
		nullifier := mustNullifierHash(t, inputHash, utxo.Blinding, nullifierSecret)
		nullifiers[i] = nullifier
		stateLeafIndices[i] = defaultStateLeafIndex(i)
		stateEntries[stateLeafIndices[i]] = inputHash
	}
	stateRoot, stateProofs := mustBuildSparseStateTree(t, stateEntries)
	statePathVars := make([][]frontend.Variable, shape.NInputs)
	stateDirVars := make([][]frontend.Variable, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		statePathVars[i] = make([]frontend.Variable, model.StateTreeHeight)
		stateDirVars[i] = make([]frontend.Variable, model.StateTreeHeight)
		for j := 0; j < model.StateTreeHeight; j++ {
			statePathVars[i][j] = fe(0)
			stateDirVars[i][j] = fe(0)
		}
		proof := stateProofs[stateLeafIndices[i]]
		fillStateProofVariables(statePathVars[i], stateDirVars[i], proof)
	}

	nullifierTree := mustNewIndexedTree(t)
	nfLowValueVars := make([]frontend.Variable, shape.NInputs)
	nfNextValueVars := make([]frontend.Variable, shape.NInputs)
	nfLowPathVars := make([][]frontend.Variable, shape.NInputs)
	nfLowDirVars := make([][]frontend.Variable, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		nfLowValueVars[i] = fe(0)
		nfNextValueVars[i] = fe(0)
		nfLowPathVars[i] = make([]frontend.Variable, model.NullifierTreeHeight)
		nfLowDirVars[i] = make([]frontend.Variable, model.NullifierTreeHeight)
		for j := 0; j < model.NullifierTreeHeight; j++ {
			nfLowPathVars[i][j] = fe(0)
			nfLowDirVars[i][j] = fe(0)
		}
		witness := mustNonInclusion(t, nullifierTree, asBigInt(nullifiers[i]))
		nfLowValueVars[i] = witness.LowValue
		nfNextValueVars[i] = witness.NextValue
		fillStateProofVariables(nfLowPathVars[i], nfLowDirVars[i], model.StateTreeWitness{
			Siblings:   witness.Siblings,
			Directions: witness.Directions,
		})
	}
	utxoTreeRoots := repeatBigInt(stateRoot, shape.NInputs)
	nullifierRoots := repeatBigInt(nullifierTree.Root(), shape.NInputs)

	outputCircuitUtxos := make([]UtxoCircuitFields, shape.NOutputs)
	outputHashes := make([]*big.Int, shape.NOutputs)
	outputHashVariables := make([]frontend.Variable, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		utxo := outputUtxos[i]
		outputCircuitUtxos[i] = toCircuitFields(utxo)
		outputHash := mustUtxoHash(t, utxo)
		outputHashes[i] = outputHash
		outputHashVariables[i] = outputHash
	}

	externalDataHash := fe(300)
	expiry := fe(400)
	privateTxHash := mustPrivateTxHash(t, inputHashes, outputHashes, externalDataHash, expiry)
	privateTxHashBytes := mustFieldBytes(t, privateTxHash)
	p256Pub, p256Sig, err := inactiveP256Witness(privateTxHashBytes[:])
	if err != nil {
		t.Fatalf("inactive P256 witness: %v", err)
	}
	solanaPubkeyHash := testSolanaSignerHash()

	publicInputs := model.PublicInputs{
		Nullifiers:           toBigInts(nullifiers),
		OutputUtxoHashes:     outputHashes,
		UtxoTreeRoots:        utxoTreeRoots,
		NullifierRoots:       nullifierRoots,
		PrivateTxHash:        privateTxHash,
		ExternalDataHash:     externalDataHash,
		PublicSolAmount:      model.SignedToFe(publicSolAmount),
		PublicSplAmount:      model.SignedToFe(publicSplAmount),
		PublicSplAssetPubkey: publicSplAssetPubkey,
		ProgramIDHashchain:   fe(0),
		SolanaPubkeyHash:     solanaPubkeyHash,
		SolanaPkHashes:       toBigInts(solanaPkHashes),
		DataHash:             fe(0),
		ZoneDataHash:         fe(0),
	}
	publicInputHashValue, err := model.PublicInputHash(publicInputs)
	publicInputHash := mustHash(t, publicInputHashValue, err)

	inputs := make([]Input, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		inputs[i] = Input{
			Utxo:          inputCircuitUtxos[i],
			StatePath:     statePathVars[i],
			StatePathDirs: stateDirVars[i],
			NfLowValue:    nfLowValueVars[i],
			NfNextValue:   nfNextValueVars[i],
			NfLowPath:     nfLowPathVars[i],
			NfLowPathDirs: nfLowDirVars[i],
			UtxoTreeRoot:  utxoTreeRoots[i],
			NullifierRoot: nullifierRoots[i],
			Nullifier:     nullifiers[i],
			SolanaPkHash:  solanaPkHashes[i],
		}
	}
	outputs := make([]Output, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		outputs[i] = Output{
			Utxo: outputCircuitUtxos[i],
			Hash: outputHashVariables[i],
		}
	}

	return &Circuit{
		Shape:                shape,
		Inputs:               inputs,
		Outputs:              outputs,
		ExternalDataHash:     externalDataHash,
		ExpiryUnixTs:         expiry,
		NullifierSecret:      nullifierSecret,
		P256Pub:              p256Pub,
		P256Sig:              p256Sig,
		PrivateTxHash:        privateTxHash,
		PublicSolAmount:      publicInputs.PublicSolAmount,
		PublicSplAmount:      publicInputs.PublicSplAmount,
		PublicSplAssetPubkey: publicInputs.PublicSplAssetPubkey,
		ProgramIDHashchain:   publicInputs.ProgramIDHashchain,
		SolanaPubkeyHash:     publicInputs.SolanaPubkeyHash,
		DataHash:             publicInputs.DataHash,
		ZoneDataHash:         publicInputs.ZoneDataHash,
		PublicInputHash:      publicInputHash,
	}
}

func defaultStateLeafIndex(i int) uint64 {
	return uint64(17 + i)
}

func fillStateProofVariables(path []frontend.Variable, dirs []frontend.Variable, proof model.StateTreeWitness) {
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
	publicInputs := model.PublicInputs{
		Nullifiers:           toBigInts(assignment.inputNullifiers()),
		OutputUtxoHashes:     toBigInts(assignment.outputHashes()),
		UtxoTreeRoots:        toBigInts(assignment.inputUtxoRoots()),
		NullifierRoots:       toBigInts(assignment.inputNullifierRoots()),
		PrivateTxHash:        asBigInt(assignment.PrivateTxHash),
		ExternalDataHash:     asBigInt(assignment.ExternalDataHash),
		PublicSolAmount:      asBigInt(assignment.PublicSolAmount),
		PublicSplAmount:      asBigInt(assignment.PublicSplAmount),
		PublicSplAssetPubkey: asBigInt(assignment.PublicSplAssetPubkey),
		ProgramIDHashchain:   asBigInt(assignment.ProgramIDHashchain),
		SolanaPubkeyHash:     asBigInt(assignment.SolanaPubkeyHash),
		SolanaPkHashes:       toBigInts(assignment.inputSolanaPkHashes()),
		DataHash:             asBigInt(assignment.DataHash),
		ZoneDataHash:         asBigInt(assignment.ZoneDataHash),
	}
	publicInputHashValue, err := model.PublicInputHash(publicInputs)
	assignment.PublicInputHash = mustHash(t, publicInputHashValue, err)
}

func defaultBalancedUtxos(t *testing.T, shape model.Shape) ([]model.Utxo, []model.Utxo) {
	t.Helper()

	assetID := fe(7)
	inputs := make([]model.Utxo, shape.NInputs)
	total := int64(0)
	for i := 0; i < shape.NInputs; i++ {
		amount := int64(100 + i*10)
		inputs[i] = sampleUtxoWithAssetAndAmount(10+i*10, assetID, fe(amount))
		total += amount
	}
	outputs := make([]model.Utxo, shape.NOutputs)
	remaining := total
	for i := 0; i < shape.NOutputs; i++ {
		amount := remaining / int64(shape.NOutputs-i)
		remaining -= amount
		outputs[i] = sampleUtxoWithAssetAndAmount(100+i*10, assetID, fe(amount))
	}
	return inputs, outputs
}

func sampleUtxoWithAssetAndAmount(base int, assetID, amount *big.Int) model.Utxo {
	utxo := sampleUtxo(base)
	utxo.AssetID = new(big.Int).Set(assetID)
	utxo.AssetAmount = new(big.Int).Set(amount)
	return utxo
}

func twoOutputUtxos(output model.Utxo) []model.Utxo {
	return []model.Utxo{
		output,
		sampleUtxoWithAssetAndAmount(110, output.AssetID, fe(0)),
	}
}

func sampleUtxo(base int) model.Utxo {
	return model.Utxo{
		Domain:        fe(int64(base + 1)),
		Owner:         testOwnerHashForNullifierSecret(fe(99)),
		AssetID:       fe(int64(base + 3)),
		AssetAmount:   fe(int64(base + 4)),
		Blinding:      fe(int64(base + 5)),
		DataHash:      fe(int64(base + 6)),
		ZoneDataHash:  fe(int64(base + 7)),
		ZoneProgramID: fe(int64(base + 8)),
	}
}

func rewriteSingleInputAsP256(t *testing.T, assignment *Circuit, ownerPriv, signingPriv *ecdsa.PrivateKey) {
	t.Helper()
	if len(assignment.Inputs) != 1 {
		t.Fatalf("rewriteSingleInputAsP256 expects one input, got %d", len(assignment.Inputs))
	}
	nullifierSecret := asBigInt(assignment.NullifierSecret)
	nullifierPk := mustNullifierPk(t, nullifierSecret)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), ownerPriv.PublicKey.X, ownerPriv.PublicKey.Y)
	ownerKeyHash, err := model.P256OwnerKeyHash(compressed)
	if err != nil {
		t.Fatalf("P256 owner key hash: %v", err)
	}
	owner, err := model.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		t.Fatalf("P256 owner hash: %v", err)
	}
	assignment.Inputs[0].Utxo.Owner = owner
	assignment.Inputs[0].SolanaPkHash = fe(0)

	inputHash := mustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[0].Utxo))
	stateEntries := map[uint64]*big.Int{defaultStateLeafIndex(0): inputHash}
	stateRoot, stateProofs := mustBuildSparseStateTree(t, stateEntries)
	fillStateProofVariables(assignment.Inputs[0].StatePath, assignment.Inputs[0].StatePathDirs, stateProofs[defaultStateLeafIndex(0)])
	assignment.Inputs[0].UtxoTreeRoot = stateRoot

	nullifier := mustNullifierHash(t, inputHash, asBigInt(assignment.Inputs[0].Utxo.Blinding), nullifierSecret)
	assignment.Inputs[0].Nullifier = nullifier
	nullifierTree := mustNewIndexedTree(t)
	nfWitness := mustNonInclusion(t, nullifierTree, nullifier)
	assignment.Inputs[0].NfLowValue = nfWitness.LowValue
	assignment.Inputs[0].NfNextValue = nfWitness.NextValue
	fillStateProofVariables(assignment.Inputs[0].NfLowPath, assignment.Inputs[0].NfLowPathDirs, model.StateTreeWitness{
		Siblings:   nfWitness.Siblings,
		Directions: nfWitness.Directions,
	})
	assignment.Inputs[0].NullifierRoot = nullifierTree.Root()

	outputHashes := toBigInts(assignment.outputHashes())
	privateTxHash := mustPrivateTxHash(
		t,
		[]*big.Int{inputHash},
		outputHashes,
		asBigInt(assignment.ExternalDataHash),
		asBigInt(assignment.ExpiryUnixTs),
	)
	assignment.PrivateTxHash = privateTxHash
	msg := mustFieldBytes(t, privateTxHash)
	r, s, err := ecdsa.Sign(rand.Reader, signingPriv, msg[:])
	if err != nil {
		t.Fatalf("sign P256 private tx hash: %v", err)
	}
	assignment.P256Pub = p256PubkeyAssignment(ownerPriv)
	assignment.P256Sig = gnarkecdsa.Signature[emulated.P256Fr]{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}
	refreshPublicInputHash(t, assignment)
}

func p256PubkeyAssignment(priv *ecdsa.PrivateKey) gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr] {
	return gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.X),
		Y: emulated.ValueOf[emulated.P256Fp](priv.PublicKey.Y),
	}
}

func mustFixedP256Key(t *testing.T, scalar int64) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := p256key.PrivateKeyFromScalar(big.NewInt(scalar))
	if err != nil {
		t.Fatalf("fixed P256 key: %v", err)
	}
	return priv
}

func testOwnerHashForNullifierSecret(nullifierSecret *big.Int) *big.Int {
	nullifierPk, err := model.NullifierPk(nullifierSecret)
	if err != nil {
		panic(err)
	}
	owner, err := model.OwnerHash(testSolanaPkHash(nil), nullifierPk)
	if err != nil {
		panic(err)
	}
	return owner
}

func testSolanaSignerHash() *big.Int {
	return model.HashToFieldSize(testSolanaSignerPubkey())
}

func testSolanaPkHash(t *testing.T) *big.Int {
	pubkey := testSolanaSignerPubkey()
	var bytes [32]byte
	copy(bytes[:], pubkey)
	hash, err := model.SolanaPkHash(bytes)
	if err != nil {
		if t != nil {
			t.Fatalf("solana pk hash: %v", err)
		}
		panic(err)
	}
	return hash
}

func testSolanaSignerPubkey() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	key := ed25519.NewKeyFromSeed(seed)
	return key[32:]
}

func toCircuitFields(utxo model.Utxo) UtxoCircuitFields {
	return UtxoCircuitFields{
		Domain:        utxo.Domain,
		Owner:         utxo.Owner,
		AssetID:       utxo.AssetID,
		AssetAmount:   utxo.AssetAmount,
		Blinding:      utxo.Blinding,
		DataHash:      utxo.DataHash,
		ZoneDataHash:  utxo.ZoneDataHash,
		ZoneProgramID: utxo.ZoneProgramID,
	}
}

func circuitFieldsToUtxo(fields UtxoCircuitFields) model.Utxo {
	return model.Utxo{
		Domain:        asBigInt(fields.Domain),
		Owner:         asBigInt(fields.Owner),
		AssetID:       asBigInt(fields.AssetID),
		AssetAmount:   asBigInt(fields.AssetAmount),
		Blinding:      asBigInt(fields.Blinding),
		DataHash:      asBigInt(fields.DataHash),
		ZoneDataHash:  asBigInt(fields.ZoneDataHash),
		ZoneProgramID: asBigInt(fields.ZoneProgramID),
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
