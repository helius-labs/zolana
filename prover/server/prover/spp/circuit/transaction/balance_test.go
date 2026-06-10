package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

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
