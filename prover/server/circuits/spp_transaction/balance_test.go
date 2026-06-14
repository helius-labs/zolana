package transaction_test

import (
	"math/big"
	"testing"
	. "zolana/prover/circuits/spp_transaction"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

func TestCircuitRejectsBalanceMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	asset := spptest.Fe(7)
	inputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(100)),
	}
	outputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(40)),
		sampleUtxoWithAssetAndAmount(110, asset, spptest.Fe(70)),
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
	abstractor.CallVoid(api, RangeCheckSigned64{Value: c.Value})
	return nil
}

func TestSignedAmountRangeBoundary(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &signedAmountRangeCircuit{}
	limit := new(big.Int).Lsh(big.NewInt(1), AmountBits)

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
	solAsset := protocol.SolAsset()

	t.Run("deposit", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewCircuit(Shape(shape))
		assignment := buildCircuitAssignmentFromUtxos(
			t,
			shape,
			[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
			twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(125))),
			big.NewInt(25),
			big.NewInt(0),
			spptest.Fe(0),
		)

		assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	})

	t.Run("withdraw", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewCircuit(Shape(shape))
		assignment := buildCircuitAssignmentFromUtxos(
			t,
			shape,
			[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
			twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(75))),
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
	circuit := MustNewCircuit(Shape(shape))
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
	circuit := MustNewCircuit(Shape(shape))
	privateAsset := spptest.Fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, privateAsset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, privateAsset, spptest.Fe(125))),
		big.NewInt(0),
		big.NewInt(25),
		spptest.Fe(88),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsPublicSplMovementOnSolAsset(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	solAsset := protocol.SolAsset()
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(125))),
		big.NewInt(0),
		big.NewInt(25),
		solAsset,
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsPhantomPublicSplMovement(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	privateAsset := spptest.Fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, privateAsset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, privateAsset, spptest.Fe(100))),
		big.NewInt(0),
		big.NewInt(25),
		spptest.Fe(88),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Pure private transfer of two distinct SPL assets: each conserved on its own
// (multiple SPLs per transaction, no public movement).
func TestCircuitConservesTwoDistinctAssets(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	a := spptest.Fe(77)
	b := spptest.Fe(91)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(10, a, spptest.Fe(100)),
			sampleUtxoWithAssetAndAmount(20, b, spptest.Fe(50)),
		},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, a, spptest.Fe(100)),
			sampleUtxoWithAssetAndAmount(110, b, spptest.Fe(50)),
		},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Conservation is per-asset, not total: a transaction whose total balances but
// whose per-asset balance does not (asset a short by 10, asset b over by 10)
// must be rejected — the cross-asset value-conversion attack.
func TestCircuitRejectsCrossAssetValueConversion(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	a := spptest.Fe(77)
	b := spptest.Fe(91)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(10, a, spptest.Fe(100)),
			sampleUtxoWithAssetAndAmount(20, b, spptest.Fe(50)),
		},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, a, spptest.Fe(90)),
			sampleUtxoWithAssetAndAmount(110, b, spptest.Fe(60)),
		},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// A public SPL deposit on asset a coexists with a purely private transfer of
// asset b in one proof: a absorbs the public adjustment, b conserves on its own.
func TestCircuitConservesPublicSplAlongsidePrivateAsset(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	publicAsset := spptest.Fe(77)
	privateAsset := spptest.Fe(91)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(10, publicAsset, spptest.Fe(100)),
			sampleUtxoWithAssetAndAmount(20, privateAsset, spptest.Fe(50)),
		},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, publicAsset, spptest.Fe(125)),
			sampleUtxoWithAssetAndAmount(110, privateAsset, spptest.Fe(50)),
		},
		big.NewInt(0),
		big.NewInt(25),
		publicAsset,
	)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// SPL unshield (withdraw): the symmetric partner to TestCircuitAcceptsPublicSplDeposit.
func TestCircuitAcceptsPublicSplWithdraw(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	asset := spptest.Fe(77)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(125))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(100))),
		big.NewInt(0),
		big.NewInt(-25),
		asset,
	)
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// The public SPL mint id must be 0 when no SPL amount moves: a balanced,
// otherwise-valid transfer carrying a stray publicSplAssetPubkey is rejected,
// so a no-public-SPL transaction cannot leak a mint id into the transcript.
func TestCircuitRejectsNonZeroPublicSplAssetWithoutAmount(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	asset := spptest.Fe(7)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(100))),
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(88),
	)
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
