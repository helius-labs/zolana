package shared_test

import (
	"math/big"
	"testing"
	. "zolana/prover/circuits/spp_transaction/shared"

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
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	asset := spptest.Fe(7)
	inputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(100)),
	}
	outputs := []protocol.Utxo{
		sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(40)),
		sampleUtxoWithAssetAndAmount(110, asset, spptest.Fe(70)),
	}
	assignment := buildCircuitAssignmentFromUtxos(t, shape, inputs, outputs)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
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
		circuit := MustNewCustomZoneP256Circuit(Shape(shape))
		assets, amounts := solPublicSlot(25)
		assignment := buildCircuitAssignmentExact(
			t,
			shape,
			[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
			twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(125))),
			assets,
			amounts,
		)

		assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
	})

	t.Run("withdraw", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewCustomZoneP256Circuit(Shape(shape))
		assets, amounts := solPublicSlot(-25)
		assignment := buildCircuitAssignmentExact(
			t,
			shape,
			[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
			twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(75))),
			assets,
			amounts,
		)

		assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
	})
}

// Slots are uniform: SOL may move through the second slot just like any other
// asset.
func TestCircuitAcceptsPublicSolMovementInSecondSlot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	solAsset := protocol.SolAsset()
	assets, amounts := splPublicSlot(solAsset, 25)
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(125))),
		assets,
		amounts,
	)

	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

func TestCircuitAcceptsPublicSplDeposit(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	publicAsset := spptest.Fe(77)
	assets, amounts := splPublicSlot(publicAsset, 25)
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, publicAsset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, publicAsset, spptest.Fe(125))),
		assets,
		amounts,
	)

	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsPublicSplAssetMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	privateAsset := spptest.Fe(77)
	assets, amounts := splPublicSlot(spptest.Fe(88), 25)
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, privateAsset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, privateAsset, spptest.Fe(125))),
		assets,
		amounts,
	)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// Two active slots must name distinct assets: splitting one public movement
// across both slots on the same asset is rejected even though the sums balance.
func TestCircuitRejectsDuplicateActivePublicAssets(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	asset := spptest.Fe(77)
	assets := [NPublicSlots]*big.Int{new(big.Int).Set(asset), new(big.Int).Set(asset)}
	amounts := [NPublicSlots]*big.Int{big.NewInt(10), big.NewInt(15)}
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(125))),
		assets,
		amounts,
	)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsPhantomPublicSplMovement(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	privateAsset := spptest.Fe(77)
	assets, amounts := splPublicSlot(spptest.Fe(88), 25)
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, privateAsset, spptest.Fe(100))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, privateAsset, spptest.Fe(100))),
		assets,
		amounts,
	)

	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// Pure private transfer of two distinct SPL assets: each conserved on its own
// (multiple SPLs per transaction, no public movement).
func TestCircuitConservesTwoDistinctAssets(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
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
	)
	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// Conservation is per-asset, not total: a transaction whose total balances but
// whose per-asset balance does not (asset a short by 10, asset b over by 10)
// must be rejected — the cross-asset value-conversion attack.
func TestCircuitRejectsCrossAssetValueConversion(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
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
	)
	assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// A public SPL deposit on asset a coexists with a purely private transfer of
// asset b in one proof: a absorbs the public adjustment, b conserves on its own.
func TestCircuitConservesPublicSplAlongsidePrivateAsset(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	publicAsset := spptest.Fe(77)
	privateAsset := spptest.Fe(91)
	assets, amounts := splPublicSlot(publicAsset, 25)
	assignment := buildCircuitAssignmentExact(
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
		assets,
		amounts,
	)
	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// SPL unshield (withdraw): the symmetric partner to TestCircuitAcceptsPublicSplDeposit.
func TestCircuitAcceptsPublicSplWithdraw(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	asset := spptest.Fe(77)
	assets, amounts := splPublicSlot(asset, -25)
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(125))},
		twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(100))),
		assets,
		amounts,
	)
	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// C-01: the balance circuit conserves each active slot on independent per-asset
// equations with no mutual-exclusion constraint, so one proof may carry both a
// positive SOL amount and a positive SPL amount and mint value in both assets
// at once. This is the enabling condition for the on-chain settlement bug (the
// program settles only the SPL leg, leaving the SOL leg unbacked). A
// mutual-exclusion constraint here would make this witness unsatisfiable.
func TestCircuitAcceptsSimultaneousSolAndSplDeposit(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCustomZoneP256Circuit(Shape(shape))
	solAsset := protocol.SolAsset()
	splAsset := spptest.Fe(77)

	assets := [NPublicSlots]*big.Int{protocol.SolAsset(), new(big.Int).Set(splAsset)}
	amounts := [NPublicSlots]*big.Int{big.NewInt(25), big.NewInt(25)}

	// No prior value: both inputs are zero-amount; the two outputs are funded
	// entirely by the two simultaneous public deposits (25 SOL and 25 SPL).
	assignment := buildCircuitAssignmentExact(
		t,
		shape,
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(0)),
			sampleUtxoWithAssetAndAmount(20, splAsset, spptest.Fe(0)),
		},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(25)),
			sampleUtxoWithAssetAndAmount(110, splAsset, spptest.Fe(25)),
		},
		assets,
		amounts,
	)

	assert.SolvingSucceeded(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
}

// An asset id is public only while it moves: a balanced, otherwise-valid
// transfer carrying a stray asset id in a zero-amount slot is rejected, so a
// no-public-movement transaction cannot leak an asset id into the transcript.
func TestCircuitRejectsNonZeroPublicAssetWithoutAmount(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	asset := spptest.Fe(7)

	for name, slot := range map[string]int{"first_slot": 0, "second_slot": 1} {
		t.Run(name, func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := MustNewCustomZoneP256Circuit(Shape(shape))
			assets, amounts := noPublicSlots()
			assets[slot] = spptest.Fe(88)
			assignment := buildCircuitAssignmentExact(
				t,
				shape,
				[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(100))},
				twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(100))),
				assets,
				amounts,
			)
			assert.SolvingFailed(circuit, asCustomZoneP256(assignment), test.WithCurves(ecc.BN254))
		})
	}
}
