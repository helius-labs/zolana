package shared_test

import (
	"math/big"
	"testing"

	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// Distinct test tree ids so a swapped input/output id is caught.
const (
	testInputTreeID  = 7
	testOutputTreeID = 11
)

// testUtxoHash mirrors utxoHashGadget:
// Poseidon(domain, treeID, asset, amount, dataHash, ringHash, ownerUtxoHash).
// protocol.UtxoHash still hashes the six-field preimage, so the circuit tests
// carry their own mirror until the host follows.
func testUtxoHash(t testing.TB, u protocol.Utxo, treeID frontend.Variable) *big.Int {
	t.Helper()
	ownerUtxoHash, err := protocol.OwnerUtxoHash(u.Owner, u.Blinding)
	ownerUtxoHash = spptest.MustHash(t, ownerUtxoHash, err)
	ringHash, err := poseidon.Hash([]*big.Int{u.RingDataHash, u.RingProgramID})
	ringHash = spptest.MustHash(t, ringHash, err)
	h, err := poseidon.Hash([]*big.Int{
		u.Domain,
		spptest.AsBigInt(treeID),
		u.Asset,
		u.Amount,
		u.DataHash,
		ringHash,
		ownerUtxoHash,
	})
	return spptest.MustHash(t, h, err)
}

// testPublicInputHash mirrors Transaction.publicInputHash: protocol's preimage
// with the two tree ids inserted after the nullifier-tree-root chain.
func testPublicInputHash(t testing.TB, inputs protocol.PublicInputs, inputTreeID, outputTreeID frontend.Variable) *big.Int {
	t.Helper()
	fields := []*big.Int{
		spptest.MustHashChain(t, inputs.Nullifiers),
		spptest.MustHashChain(t, inputs.OutputUtxoHashes),
		spptest.MustHashChain(t, inputs.UtxoTreeRoots),
		spptest.MustHashChain(t, inputs.NullifierTreeRoots),
		spptest.AsBigInt(inputTreeID),
		spptest.AsBigInt(outputTreeID),
		inputs.PrivateTxHash,
		inputs.ExternalDataHash,
	}
	for i := 0; i < NPublicSlots; i++ {
		fields = append(fields, inputs.PublicAssets[i], inputs.PublicAmounts[i])
	}
	signerChain, err := protocol.RightHashChain(inputs.SignerPkHashes)
	fields = append(fields, inputs.RingProgramID, spptest.MustHash(t, signerChain, err), inputs.AllowDummyInputs)
	if inputs.BindOutputOwnerTags {
		fields = append(fields, spptest.MustHashChain(t, inputs.OutputOwnerPkHashes))
	}
	return spptest.MustHashChain(t, fields)
}

type utxoHashPinCircuit struct {
	Utxo   UtxoCircuitFields
	TreeID frontend.Variable
	Hash   frontend.Variable `gnark:",public"`
}

func (c *utxoHashPinCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(UtxoHashCircuit(api, c.Utxo, c.TreeID), c.Hash)
	return nil
}

// The in-circuit utxo hash equals the seven-field native preimage, and the tree
// id is part of it.
func TestUtxoHashCircuitBindsTreeID(t *testing.T) {
	assert := test.NewAssert(t)
	utxo := sampleUtxo(1)
	assignment := &utxoHashPinCircuit{
		Utxo:   fieldsFromUtxo(utxo),
		TreeID: spptest.Fe(testInputTreeID),
		Hash:   testUtxoHash(t, utxo, spptest.Fe(testInputTreeID)),
	}
	assert.SolvingSucceeded(&utxoHashPinCircuit{}, assignment, test.WithCurves(ecc.BN254))

	assignment.TreeID = spptest.Fe(testOutputTreeID)
	assert.SolvingFailed(&utxoHashPinCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

// Publishing another input tree id breaks inclusion: the leaves were hashed
// under the fixture's input tree.
func TestCircuitRejectsInputTreeIDMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.InputTreeID = spptest.Fe(testOutputTreeID)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// Publishing another output tree id breaks the output hash binding.
func TestCircuitRejectsOutputTreeIDMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.OutputTreeID = spptest.Fe(testInputTreeID)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
