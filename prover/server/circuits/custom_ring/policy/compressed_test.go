package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	merkletree "zolana/prover/merkle-tree"
	"zolana/prover/prover-test/spp/spptest"
)

// compressedRoundTrip is a valid windowed-velocity witness with the head map
// framed to a transfer of the record to its successor.
func compressedRoundTrip(t *testing.T) *CompressedPolicyCircuit {
	t.Helper()
	f := velocityDefault()
	listFacts := f.listFacts
	if f.velocity.rulesFree {
		f.rulesFree = true
		listFacts = nil
	}
	s := newStatement(t, f)
	c := s.assignment(t, listFacts)

	zero := big.NewInt(0)
	pMinusOne := new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	member := spptest.AsBigInt(c.Inputs[0].OwnerPkHash)
	recordIn := s.inputs[len(s.inputs)-1]
	recordOut := s.outputs[len(s.outputs)-1]
	spent := spptest.MustNullifier(t, hostUtxoHash(t, recordIn), spptest.AsBigInt(recordIn.Blinding), zero)
	successor := spptest.MustNullifier(t, hostUtxoHash(t, recordOut), spptest.AsBigInt(recordOut.Blinding), zero)

	tree := merkletree.NewTree(HeadMapHeight)
	tree.Update(0, headLeafValue(zero, pMinusOne, zero))
	tree.Update(0, headLeafValue(zero, member, zero))
	tree.Update(1, headLeafValue(member, pMinusOne, spent))
	oldRoot := tree.Root.Value()
	proof := tree.GenerateProof(1)
	tree.Update(1, headLeafValue(member, pMinusOne, successor))
	newRoot := tree.Root.Value()

	elements := s.keys.ChainElements(t, s.privateTxHash)
	c.PublicInputHash = spptest.MustHashChain(t, append(elements,
		s.policyHash, s.stateRoot, s.nullifierRoot, big.NewInt(entriesTreeID),
		s.ringID, s.ownOwnerHash, new(big.Int).SetUint64(s.windowIndex), boolVar(s.approval),
		&oldRoot, &newRoot,
	))

	assignment := &CompressedPolicyCircuit{
		Policy:      *c,
		HeadOldRoot: oldRoot,
		HeadNewRoot: newRoot,
		HeadNext:    pMinusOne,
		HeadIndex:   big.NewInt(1),
	}
	for i := range assignment.HeadProof {
		assignment.HeadProof[i] = proof[i]
	}
	return assignment
}

func TestCompressedCircuitSolvesHeadTransition(t *testing.T) {
	test.NewAssert(t).SolvingSucceeded(
		&CompressedPolicyCircuit{}, compressedRoundTrip(t), test.WithCurves(ecc.BN254),
	)
}

// Rejects a head proof off the member's own leaf.
func TestCompressedCircuitRejectsForeignRecord(t *testing.T) {
	assignment := compressedRoundTrip(t)
	assignment.HeadProof[0] = big.NewInt(0x1234)
	test.NewAssert(t).SolvingFailed(
		&CompressedPolicyCircuit{}, assignment, test.WithCurves(ecc.BN254),
	)
}
