package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	merkletree "zolana/prover/merkle-tree"
	"zolana/prover/prover-test/spp/spptest"
)

// registerRoundTrip splices the sentinel to the member and appends the genesis
// leaf, framing the register transition the reference tree computes.
func registerRoundTrip(t *testing.T) *CompressedRegisterCircuit {
	t.Helper()
	zero := big.NewInt(0)
	pMinusOne := new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	member := big.NewInt(0x1234)
	genesis := big.NewInt(0x5e)

	tree := merkletree.NewTree(HeadMapHeight)
	tree.Update(0, headLeafValue(zero, pMinusOne, zero))
	oldRoot := tree.Root.Value()
	lowProof := tree.GenerateProof(0)
	tree.Update(0, headLeafValue(zero, member, zero))
	newProof := tree.GenerateProof(1)
	tree.Update(1, headLeafValue(member, pMinusOne, genesis))
	newRoot := tree.Root.Value()

	hash := spptest.MustHashChain(t, []*big.Int{&oldRoot, &newRoot, member, genesis, big.NewInt(1)})
	assignment := &CompressedRegisterCircuit{
		PublicInputHash: hash,
		HeadOldRoot:     oldRoot,
		HeadNewRoot:     newRoot,
		Member:          member,
		Genesis:         genesis,
		NewIndex:        big.NewInt(1),
		LowMember:       zero,
		LowNext:         pMinusOne,
		LowNullifier:    zero,
		LowIndex:        zero,
	}
	for i := range assignment.LowProof {
		assignment.LowProof[i] = lowProof[i]
	}
	for i := range assignment.NewProof {
		assignment.NewProof[i] = newProof[i]
	}
	return assignment
}

func TestCompressedRegisterSolves(t *testing.T) {
	test.NewAssert(t).SolvingSucceeded(
		&CompressedRegisterCircuit{}, registerRoundTrip(t), test.WithCurves(ecc.BN254),
	)
}

// Rejects an insertion at a slot the empty-leaf proof does not open.
func TestCompressedRegisterRejectsOccupiedSlot(t *testing.T) {
	assignment := registerRoundTrip(t)
	assignment.NewProof[0] = big.NewInt(0x99)
	test.NewAssert(t).SolvingFailed(
		&CompressedRegisterCircuit{}, assignment, test.WithCurves(ecc.BN254),
	)
}

// The public input binds the member, an insertion for a different member than
// the proof pins is refused.
func TestCompressedRegisterRejectsWrongMember(t *testing.T) {
	assignment := registerRoundTrip(t)
	assignment.Member = big.NewInt(0x4321)
	test.NewAssert(t).SolvingFailed(
		&CompressedRegisterCircuit{}, assignment, test.WithCurves(ecc.BN254),
	)
}
