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

// testInputTreeID is slot 0's tree id; testOutputTreeID is distinct from every
// slot id so a swapped input/output id is caught.
const (
	testInputTreeID  = 7
	testOutputTreeID = 11
)

// testSlotTreeIDs returns InputTrees distinct tree ids, slot 0 = testInputTreeID.
func testSlotTreeIDs() []frontend.Variable {
	ids := []int64{testInputTreeID, 17, 19, 23, 29}
	out := make([]frontend.Variable, InputTrees)
	for k := range out {
		out[k] = spptest.Fe(ids[k])
	}
	return out
}

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
// with the tree slots, the nullifier root chain, and the output tree id after the
// output hash chain. The root fields of `inputs` are ignored.
func testPublicInputHash(
	t testing.TB,
	inputs protocol.PublicInputs,
	treeIDs, utxoTreeRoots, nullifierTreeRoots []frontend.Variable,
	outputTreeID frontend.Variable,
) *big.Int {
	t.Helper()
	fields := []*big.Int{
		spptest.MustHashChain(t, inputs.Nullifiers),
		spptest.MustHashChain(t, inputs.OutputUtxoHashes),
		spptest.MustHashChain(t, spptest.ToBigInts(treeIDs)),
		spptest.MustHashChain(t, spptest.ToBigInts(utxoTreeRoots)),
		spptest.MustHashChain(t, spptest.ToBigInts(nullifierTreeRoots)),
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

// An input hashed under slot 0 cannot claim slot 1: the slot's tree id enters
// the utxo hash, so the leaf is no longer under the root.
func TestCircuitRejectsInputClaimingOtherSlot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].TreeSlot = spptest.Fe(1)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// A slot index outside the published slots selects no tree and is rejected.
func TestCircuitRejectsOutOfRangeTreeSlot(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].TreeSlot = spptest.Fe(InputTrees)

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
