package transaction

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"light/light-prover/prover/poseidon"
	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
)

func TestCircuitCompilesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
		shape := shape
		t.Run(shape.String(), func(t *testing.T) {
			circuit := MustNewCircuit(shape)
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300)); err != nil {
				t.Fatalf("compile SPP circuit %s: %v", shape, err)
			}
		})
	}
}

func TestCircuitProvesForSupportedShapes(t *testing.T) {
	for _, shape := range protocol.SupportedShapes {
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

func TestCircuitRejectsBadOutputHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Outputs[0].Hash = spptest.Fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadStatePathElements(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].StatePathElements[0] = spptest.Fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadStatePathIndex(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].StatePathIndex = new(big.Int).Add(spptest.AsBigInt(assignment.Inputs[0].StatePathIndex), big.NewInt(1))

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadNullifierNonInclusionPath(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].NullifierLowPathElements[0] = spptest.Fe(999)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadNullifierRange(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].NullifierLowValue = assignment.Inputs[0].Nullifier

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadNullifierSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.NullifierSecret = spptest.Fe(998)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsDuplicateInputWithinTransaction(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := spptest.Fe(7)
	input := sampleUtxoWithAssetAndAmount(10, assetID, spptest.Fe(100))
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{input, input},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, assetID, spptest.Fe(125)),
			sampleUtxoWithAssetAndAmount(110, assetID, spptest.Fe(75)),
		},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)

	// Spending the same UTXO twice yields equal nullifiers; assertDistinctNullifiers
	// rejects it in-circuit so its amount can't be counted twice in the balance.
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsProgramOwnedInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := spptest.Fe(7)
	input := sampleUtxoWithAssetAndAmount(10, assetID, spptest.Fe(100))
	// A zone-owned input must be spent via zone_transact (zone PDA authorization),
	// not the default transact. The circuit pins zone fields to zero.
	input.ZoneProgramID = spptest.Fe(1)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{input},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, assetID, spptest.Fe(60)),
			sampleUtxoWithAssetAndAmount(110, assetID, spptest.Fe(40)),
		},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsSolanaSignerOwnerMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].SolanaPkHash = spptest.Fe(12345)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitAcceptsP256Owner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// The Solana-only circuit variant (no P256 gadget) proves a Solana-owned
// transaction. P256MessageHash must be 0 on this rail (no signature).
func TestSolanaCircuitSolvesSolanaInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewSolanaCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.P256MessageHash = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Soundness guard: the Solana-only variant must reject a P256-owned input
// (SolanaPkHash == 0), since it skips the signature gadget. Otherwise a UTXO
// owned by OwnerHash(0, nullifier_pk) could be spent with no signature.
func TestSolanaCircuitRejectsP256Input(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewSolanaCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.P256MessageHash = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Spec single-owner rule: all non-dummy inputs must share one owner. Mixing a
// P256-owned input with a Solana-owned input in one transaction is rejected.
func TestCircuitRejectsMixedP256AndSolanaInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, priv, priv)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadP256Signature(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	wrongSigner := spptest.FixedP256Key(t, 12)
	rewriteSingleInputAsP256(t, assignment, priv, wrongSigner)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadP256MessageHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.P256MessageHash = new(big.Int).Add(spptest.AsBigInt(assignment.P256MessageHash), big.NewInt(1))
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsP256PubkeyOwnerMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	ownerPriv := spptest.FixedP256Key(t, 11)
	signingPriv := spptest.FixedP256Key(t, 12)
	rewriteSingleInputAsP256(t, assignment, ownerPriv, signingPriv)
	assignment.P256Pub = spptest.P256PubkeyAssignment(signingPriv)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsOwnerHashPreimageMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].Utxo.Owner = spptest.Fe(12345)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsExternalDataHashMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.ExternalDataHash = spptest.Fe(301)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBalanceMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := spptest.Fe(7)
	inputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(10, assetID, spptest.Fe(100)),
	}
	outputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(100, assetID, spptest.Fe(40)),
		sampleUtxoWithAssetAndAmount(110, assetID, spptest.Fe(70)),
	}
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		inputs,
		outputs,
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

type signedAmountRangeCircuit struct {
	Value frontend.Variable
}

func (c *signedAmountRangeCircuit) Define(api frontend.API) error {
	rangeCheckSigned64(api, c.Value)
	return nil
}

func TestSignedAmountRangeBoundary(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &signedAmountRangeCircuit{}
	limit := new(big.Int).Lsh(big.NewInt(1), amountBits)

	assert.SolvingSucceeded(
		circuit,
		&signedAmountRangeCircuit{Value: protocol.SignedToField(new(big.Int).Sub(limit, big.NewInt(1)))},
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingSucceeded(
		circuit,
		&signedAmountRangeCircuit{Value: protocol.SignedToField(new(big.Int).Neg(limit))},
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingFailed(
		circuit,
		&signedAmountRangeCircuit{Value: protocol.SignedToField(limit)},
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingFailed(
		circuit,
		&signedAmountRangeCircuit{Value: protocol.SignedToField(new(big.Int).Sub(new(big.Int).Neg(limit), big.NewInt(1)))},
		test.WithCurves(ecc.BN254),
	)
}

func TestCircuitAcceptsPublicSolMovement(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	solAssetID := protocol.SolAsset()

	t.Run("deposit", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewCircuit(shape)
		assignment := buildCircuitAssignmentFromUtxos(
			t,
			shape,
			[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, spptest.Fe(100))},
			twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAssetID, spptest.Fe(125))),
			big.NewInt(25),
			big.NewInt(0),
			spptest.Fe(0),
		)

		assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	})

	t.Run("withdraw", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewCircuit(shape)
		assignment := buildCircuitAssignmentFromUtxos(
			t,
			shape,
			[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, spptest.Fe(100))},
			twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAssetID, spptest.Fe(75))),
			big.NewInt(-25),
			big.NewInt(0),
			spptest.Fe(0),
		)

		assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	})
}

func TestCircuitAcceptsPublicSplDeposit(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	publicSplAssetPubkey := spptest.Fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, publicSplAssetPubkey, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, publicSplAssetPubkey, spptest.Fe(125))),
		big.NewInt(0),
		big.NewInt(25),
		publicSplAssetPubkey,
	)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsPublicSplAssetMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	privateAssetID := spptest.Fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, privateAssetID, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, privateAssetID, spptest.Fe(125))),
		big.NewInt(0),
		big.NewInt(25),
		spptest.Fe(88),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsPublicSplMovementOnSolAsset(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	solAssetID := protocol.SolAsset()
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAssetID, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAssetID, spptest.Fe(125))),
		big.NewInt(0),
		big.NewInt(25),
		solAssetID,
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsPhantomPublicSplMovement(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	privateAssetID := spptest.Fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, privateAssetID, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, privateAssetID, spptest.Fe(100))),
		big.NewInt(0),
		big.NewInt(25),
		spptest.Fe(88),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func buildCircuitAssignment(t testing.TB, shape protocol.Shape) *Circuit {
	t.Helper()

	inputUtxos, outputUtxos := defaultBalancedUtxos(t, shape)
	return buildCircuitAssignmentFromUtxos(
		t,
		shape,
		inputUtxos,
		outputUtxos,
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
}

func buildCircuitAssignmentFromUtxos(
	t testing.TB,
	shape protocol.Shape,
	inputUtxos []protocol.Utxo,
	outputUtxos []protocol.Utxo,
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
	t testing.TB,
	shape protocol.Shape,
	inputUtxos []protocol.Utxo,
	outputUtxos []protocol.Utxo,
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

	nullifierSecret := spptest.Fe(99)
	inputOwnerKeyHashValue := testSolanaPkHash(t)
	inputCircuitUtxos := make([]UtxoCircuitFields, shape.NInputs)
	inputHashes := make([]*big.Int, shape.NInputs)
	solanaPkHashes := make([]frontend.Variable, shape.NInputs)
	nullifiers := make([]frontend.Variable, shape.NInputs)
	stateEntries := make(map[uint64]*big.Int)
	stateLeafIndices := make([]uint64, shape.NInputs)

	for i := 0; i < shape.NInputs; i++ {
		utxo := inputUtxos[i]
		inputCircuitUtxos[i] = FieldsFromUtxo(utxo)
		inputHash := spptest.MustUtxoHash(t, utxo)
		inputHashes[i] = inputHash
		solanaPkHashes[i] = inputOwnerKeyHashValue
		nullifier := spptest.MustNullifierHash(t, inputHash, utxo.Blinding, nullifierSecret)
		nullifiers[i] = nullifier
		stateLeafIndices[i] = defaultStateLeafIndex(i)
		stateEntries[stateLeafIndices[i]] = inputHash
	}
	stateRoot, stateProofs := spptest.MustBuildSparseStateTree(t, stateEntries)
	statePathElementsVars := make([][]frontend.Variable, shape.NInputs)
	statePathIndexVars := make([]frontend.Variable, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		statePathElementsVars[i] = spptest.ZeroVariables(protocol.StateTreeHeight)
		proof := stateProofs[stateLeafIndices[i]]
		fillStateProofElements(statePathElementsVars[i], proof.PathElements)
		statePathIndexVars[i] = new(big.Int).SetUint64(proof.PathIndex)
	}

	nullifierTree := spptest.MustNewNullifierTree(t)
	nfLowValueVars := make([]frontend.Variable, shape.NInputs)
	nfNextValueVars := make([]frontend.Variable, shape.NInputs)
	nfLowPathElementVars := make([][]frontend.Variable, shape.NInputs)
	nfLowPathIndexVars := make([]frontend.Variable, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		nfLowValueVars[i] = spptest.Fe(0)
		nfNextValueVars[i] = spptest.Fe(0)
		nfLowPathElementVars[i] = spptest.ZeroVariables(protocol.NullifierTreeHeight)
		witness := spptest.MustNonInclusion(t, nullifierTree, spptest.AsBigInt(nullifiers[i]))
		nfLowValueVars[i] = witness.LowValue
		nfNextValueVars[i] = witness.NextValue
		fillStateProofElements(nfLowPathElementVars[i], witness.PathElements)
		nfLowPathIndexVars[i] = new(big.Int).SetUint64(witness.LowIndex)
	}
	utxoTreeRoots := spptest.RepeatBigInt(stateRoot, shape.NInputs)
	nullifierRoots := spptest.RepeatBigInt(nullifierTree.Root(), shape.NInputs)

	outputCircuitUtxos := make([]UtxoCircuitFields, shape.NOutputs)
	outputHashes := make([]*big.Int, shape.NOutputs)
	outputHashVariables := make([]frontend.Variable, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		utxo := outputUtxos[i]
		outputCircuitUtxos[i] = FieldsFromUtxo(utxo)
		outputHash := spptest.MustUtxoHash(t, utxo)
		outputHashes[i] = outputHash
		outputHashVariables[i] = outputHash
	}

	externalDataHash := spptest.Fe(300)
	expiry := spptest.Fe(400)
	privateTxHash := spptest.MustPrivateTxHash(t, inputHashes, outputHashes, externalDataHash, expiry)
	p256MessageHash := spptest.MustP256MessageHash(t, privateTxHash)
	p256MessageBytes := spptest.MustFieldBytes(t, p256MessageHash)
	p256Pub, p256Sig, err := spptest.UnusedP256Witness(p256MessageBytes[:])
	if err != nil {
		t.Fatalf("unused P256 witness: %v", err)
	}
	solanaPubkeyHash := testSolanaSignerHash()

	publicInputs := protocol.PublicInputs{
		Nullifiers:           spptest.ToBigInts(nullifiers),
		OutputUtxoHashes:     outputHashes,
		UtxoTreeRoots:        utxoTreeRoots,
		NullifierRoots:       nullifierRoots,
		PrivateTxHash:        privateTxHash,
		P256MessageHash:      p256MessageHash,
		ExternalDataHash:     externalDataHash,
		PublicSolAmount:      protocol.SignedToField(publicSolAmount),
		PublicSplAmount:      protocol.SignedToField(publicSplAmount),
		PublicSplAssetPubkey: publicSplAssetPubkey,
		ProgramIDHashchain:   spptest.Fe(0),
		SolanaPubkeyHash:     solanaPubkeyHash,
		SolanaPkHashes:       spptest.ToBigInts(solanaPkHashes),
		DataHash:             spptest.Fe(0),
		ZoneDataHash:         spptest.Fe(0),
	}
	publicInputHashValue, err := protocol.PublicInputHash(publicInputs)
	publicInputHash := spptest.MustHash(t, publicInputHashValue, err)

	inputs := make([]Input, shape.NInputs)
	for i := 0; i < shape.NInputs; i++ {
		inputs[i] = Input{
			Utxo:                     inputCircuitUtxos[i],
			IsDummy:                  spptest.Fe(0),
			StatePathElements:        statePathElementsVars[i],
			StatePathIndex:           statePathIndexVars[i],
			NullifierLowValue:        nfLowValueVars[i],
			NullifierNextValue:       nfNextValueVars[i],
			NullifierLowPathElements: nfLowPathElementVars[i],
			NullifierLowPathIndex:    nfLowPathIndexVars[i],
			UtxoTreeRoot:             utxoTreeRoots[i],
			NullifierRoot:            nullifierRoots[i],
			Nullifier:                nullifiers[i],
			SolanaPkHash:             solanaPkHashes[i],
		}
	}
	outputs := make([]Output, shape.NOutputs)
	for i := 0; i < shape.NOutputs; i++ {
		outputs[i] = Output{
			Utxo:    outputCircuitUtxos[i],
			IsDummy: spptest.Fe(0),
			Hash:    outputHashVariables[i],
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
		P256MessageHash:      p256MessageHash,
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

func fillStateProofElements(pathElements []frontend.Variable, proofElements []*big.Int) {
	if len(pathElements) != len(proofElements) {
		panic("spp test: state path length mismatch")
	}
	for i := range proofElements {
		pathElements[i] = proofElements[i]
	}
}

func refreshPublicInputHash(t testing.TB, assignment *Circuit) {
	t.Helper()
	publicInputs := protocol.PublicInputs{
		Nullifiers:           spptest.ToBigInts(assignment.inputNullifiers()),
		OutputUtxoHashes:     spptest.ToBigInts(assignment.outputHashes()),
		UtxoTreeRoots:        spptest.ToBigInts(assignment.inputUtxoRoots()),
		NullifierRoots:       spptest.ToBigInts(assignment.inputNullifierRoots()),
		PrivateTxHash:        spptest.AsBigInt(assignment.PrivateTxHash),
		P256MessageHash:      spptest.AsBigInt(assignment.P256MessageHash),
		ExternalDataHash:     spptest.AsBigInt(assignment.ExternalDataHash),
		PublicSolAmount:      spptest.AsBigInt(assignment.PublicSolAmount),
		PublicSplAmount:      spptest.AsBigInt(assignment.PublicSplAmount),
		PublicSplAssetPubkey: spptest.AsBigInt(assignment.PublicSplAssetPubkey),
		ProgramIDHashchain:   spptest.AsBigInt(assignment.ProgramIDHashchain),
		SolanaPubkeyHash:     spptest.AsBigInt(assignment.SolanaPubkeyHash),
		SolanaPkHashes:       spptest.ToBigInts(assignment.inputSolanaPkHashes()),
		DataHash:             spptest.AsBigInt(assignment.DataHash),
		ZoneDataHash:         spptest.AsBigInt(assignment.ZoneDataHash),
	}
	publicInputHashValue, err := protocol.PublicInputHash(publicInputs)
	assignment.PublicInputHash = spptest.MustHash(t, publicInputHashValue, err)
}

func defaultBalancedUtxos(t testing.TB, shape protocol.Shape) ([]protocol.Utxo, []protocol.Utxo) {
	t.Helper()

	assetID := spptest.Fe(7)
	inputs := make([]protocol.Utxo, shape.NInputs)
	total := int64(0)
	for i := 0; i < shape.NInputs; i++ {
		amount := int64(100 + i*10)
		inputs[i] = sampleUtxoWithAssetAndAmount(10+i*10, assetID, spptest.Fe(amount))
		total += amount
	}
	outputs := make([]protocol.Utxo, shape.NOutputs)
	remaining := total
	for i := 0; i < shape.NOutputs; i++ {
		amount := remaining / int64(shape.NOutputs-i)
		remaining -= amount
		outputs[i] = sampleUtxoWithAssetAndAmount(100+i*10, assetID, spptest.Fe(amount))
	}
	return inputs, outputs
}

func sampleUtxoWithAssetAndAmount(base int, assetID, amount *big.Int) protocol.Utxo {
	utxo := sampleUtxo(base)
	utxo.AssetID = new(big.Int).Set(assetID)
	utxo.AssetAmount = new(big.Int).Set(amount)
	return utxo
}

func twoOutputUtxos(output protocol.Utxo) []protocol.Utxo {
	return []protocol.Utxo{
		output,
		sampleUtxoWithAssetAndAmount(110, output.AssetID, spptest.Fe(0)),
	}
}

func sampleUtxo(base int) protocol.Utxo {
	return protocol.Utxo{
		Domain:      spptest.Fe(protocol.UtxoDomain),
		Owner:       testOwnerHashForNullifierSecret(spptest.Fe(99)),
		AssetID:     spptest.Fe(int64(base + 3)),
		AssetAmount: spptest.Fe(int64(base + 4)),
		Blinding:    spptest.Fe(int64(base + 5)),
		// Default transact requires bare UTXOs (no program/policy/zone data).
		DataHash:      spptest.Fe(0),
		ZoneDataHash:  spptest.Fe(0),
		ZoneProgramID: spptest.Fe(0),
	}
}

func rewriteSingleInputAsP256(t testing.TB, assignment *Circuit, ownerPriv, signingPriv *ecdsa.PrivateKey) {
	t.Helper()
	if len(assignment.Inputs) != 1 {
		t.Fatalf("rewriteSingleInputAsP256 expects one input, got %d", len(assignment.Inputs))
	}
	rewriteInputAsP256(t, assignment, 0, ownerPriv, signingPriv)
}

func rewriteInputAsP256(
	t testing.TB,
	assignment *Circuit,
	inputIndex int,
	ownerPriv *ecdsa.PrivateKey,
	signingPriv *ecdsa.PrivateKey,
) {
	t.Helper()
	if inputIndex < 0 || inputIndex >= len(assignment.Inputs) {
		t.Fatalf("P256 input index %d out of range", inputIndex)
	}

	nullifierSecret := spptest.AsBigInt(assignment.NullifierSecret)
	nullifierPk := spptest.MustNullifierPk(t, nullifierSecret)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), ownerPriv.PublicKey.X, ownerPriv.PublicKey.Y)
	ownerKeyHash, err := protocol.P256OwnerKeyHash(compressed)
	if err != nil {
		t.Fatalf("P256 owner key hash: %v", err)
	}
	owner, err := protocol.OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		t.Fatalf("P256 owner hash: %v", err)
	}
	assignment.Inputs[inputIndex].Utxo.Owner = owner
	assignment.Inputs[inputIndex].SolanaPkHash = spptest.Fe(0)

	inputHashes := make([]*big.Int, len(assignment.Inputs))
	stateEntries := make(map[uint64]*big.Int, len(assignment.Inputs))
	for i := range assignment.Inputs {
		inputHash := spptest.MustUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[i].Utxo))
		inputHashes[i] = inputHash
		stateEntries[defaultStateLeafIndex(i)] = inputHash
	}
	stateRoot, stateProofs := spptest.MustBuildSparseStateTree(t, stateEntries)
	nullifierTree := spptest.MustNewNullifierTree(t)
	for i := range assignment.Inputs {
		stateProof := stateProofs[defaultStateLeafIndex(i)]
		fillStateProofElements(assignment.Inputs[i].StatePathElements, stateProof.PathElements)
		assignment.Inputs[i].StatePathIndex = new(big.Int).SetUint64(stateProof.PathIndex)
		assignment.Inputs[i].UtxoTreeRoot = stateRoot

		nullifier := spptest.MustNullifierHash(t, inputHashes[i], spptest.AsBigInt(assignment.Inputs[i].Utxo.Blinding), nullifierSecret)
		assignment.Inputs[i].Nullifier = nullifier
		nfWitness := spptest.MustNonInclusion(t, nullifierTree, nullifier)
		assignment.Inputs[i].NullifierLowValue = nfWitness.LowValue
		assignment.Inputs[i].NullifierNextValue = nfWitness.NextValue
		fillStateProofElements(assignment.Inputs[i].NullifierLowPathElements, nfWitness.PathElements)
		assignment.Inputs[i].NullifierLowPathIndex = new(big.Int).SetUint64(nfWitness.LowIndex)
		assignment.Inputs[i].NullifierRoot = nullifierTree.Root()
	}

	outputHashes := spptest.ToBigInts(assignment.outputHashes())
	privateTxHash := spptest.MustPrivateTxHash(
		t,
		inputHashes,
		outputHashes,
		spptest.AsBigInt(assignment.ExternalDataHash),
		spptest.AsBigInt(assignment.ExpiryUnixTs),
	)
	assignment.PrivateTxHash = privateTxHash
	p256MessageHash := spptest.MustP256MessageHash(t, privateTxHash)
	assignment.P256MessageHash = p256MessageHash
	msg := spptest.MustFieldBytes(t, p256MessageHash)
	r, s, err := ecdsa.Sign(rand.Reader, signingPriv, msg[:])
	if err != nil {
		t.Fatalf("sign P256 private tx hash: %v", err)
	}
	assignment.P256Pub = spptest.P256PubkeyAssignment(ownerPriv)
	assignment.P256Sig = gnarkecdsa.Signature[emulated.P256Fr]{
		R: emulated.ValueOf[emulated.P256Fr](r),
		S: emulated.ValueOf[emulated.P256Fr](s),
	}
	refreshPublicInputHash(t, assignment)
}

func testOwnerHashForNullifierSecret(nullifierSecret *big.Int) *big.Int {
	nullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		panic(err)
	}
	owner, err := protocol.OwnerHash(testSolanaPkHash(nil), nullifierPk)
	if err != nil {
		panic(err)
	}
	return owner
}

func testSolanaSignerHash() *big.Int {
	return protocol.Sha256BEField(testSolanaSignerPubkey())
}

func testSolanaPkHash(t testing.TB) *big.Int {
	pubkey := testSolanaSignerPubkey()
	var bytes [32]byte
	copy(bytes[:], pubkey)
	hash, err := protocol.SolanaPkHash(bytes)
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

func circuitFieldsToUtxo(fields UtxoCircuitFields) protocol.Utxo {
	return protocol.Utxo{
		Domain:        spptest.AsBigInt(fields.Domain),
		Owner:         spptest.AsBigInt(fields.Owner),
		AssetID:       spptest.AsBigInt(fields.AssetID),
		AssetAmount:   spptest.AsBigInt(fields.AssetAmount),
		Blinding:      spptest.AsBigInt(fields.Blinding),
		DataHash:      spptest.AsBigInt(fields.DataHash),
		ZoneDataHash:  spptest.AsBigInt(fields.ZoneDataHash),
		ZoneProgramID: spptest.AsBigInt(fields.ZoneProgramID),
	}
}

// The nullifier is the Poseidon image truncated to the tree's 248-bit domain
// with a canonical (< p) decomposition. Two values an attacker might try to
// substitute must both fail: the untruncated full image, and the low 248 bits
// of the alias full+p (what a NON-canonical decomposition would yield — the
// double-spend vector the canonical check exists to block).
func TestCircuitRejectsUntruncatedAndAliasNullifier(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)

	inputUtxos, _ := defaultBalancedUtxos(t, shape)
	inputHash := spptest.MustUtxoHash(t, inputUtxos[0])
	full, err := poseidon.HashWithT(4, []*big.Int{inputHash, inputUtxos[0].Blinding, spptest.Fe(99)})
	if err != nil {
		t.Fatal(err)
	}
	if full.BitLen() <= 248 {
		// The fixture's full image happens to fit 248 bits, which would make
		// the untruncated case vacuous. Deterministic fixtures make this a
		// stable property — fail loudly so the fixture gets adjusted.
		t.Fatal("fixture nullifier image fits 248 bits; pick a different fixture")
	}

	untruncated := buildCircuitAssignment(t, shape)
	untruncated.Inputs[0].Nullifier = new(big.Int).Set(full)
	assert.SolvingFailed(circuit, untruncated, test.WithCurves(ecc.BN254))

	alias := buildCircuitAssignment(t, shape)
	aliasFull := new(big.Int).Add(full, poseidon.Modulus)
	alias.Inputs[0].Nullifier = protocol.Truncate248(aliasFull)
	assert.SolvingFailed(circuit, alias, test.WithCurves(ecc.BN254))
}
