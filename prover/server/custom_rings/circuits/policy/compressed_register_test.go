package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/spp/spptest"
)

func registerRoundTrip(t *testing.T) *CompressedRegisterCircuit {
	t.Helper()
	member := big.NewInt(0x1234)
	genesis := big.NewInt(0x5e)
	insertion := spptest.NewHeadMap(t, HeadMapHeight).Register(t, member, genesis)
	newIndex := new(big.Int).SetUint64(insertion.NewIndex)

	assignment := &CompressedRegisterCircuit{
		PublicInputHash: spptest.MustHashChain(t, []*big.Int{insertion.OldRoot, insertion.NewRoot, member, genesis, newIndex}),
		HeadOldRoot:     insertion.OldRoot,
		HeadNewRoot:     insertion.NewRoot,
		Member:          member,
		Genesis:         genesis,
		NewIndex:        newIndex,
		LowMember:       insertion.Low.Member,
		LowNext:         insertion.Low.Next,
		LowNullifier:    insertion.Low.Nullifier,
		LowIndex:        insertion.LowIndex,
	}
	for i := range assignment.LowProof {
		assignment.LowProof[i] = insertion.LowProof[i]
		assignment.NewProof[i] = insertion.NewProof[i]
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

func TestCompressedRegisterRejectsWrongMember(t *testing.T) {
	assignment := registerRoundTrip(t)
	assignment.Member = big.NewInt(0x4321)
	test.NewAssert(t).SolvingFailed(
		&CompressedRegisterCircuit{}, assignment, test.WithCurves(ecc.BN254),
	)
}
