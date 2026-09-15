package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/spp/spptest"
)

func compressedRoundTrip(t *testing.T) *CompressedPolicyCircuit {
	t.Helper()
	f := velocityDefault()
	s := newStatement(t, f)
	c := s.assignment(t, f.facts())

	zero := big.NewInt(0)
	member := spptest.AsBigInt(c.Inputs[0].OwnerPkHash)
	recordIn := s.inputs[len(s.inputs)-1]
	recordOut := s.outputs[len(s.outputs)-1]
	spent := spptest.MustNullifier(t, hostUtxoHash(t, recordIn), spptest.AsBigInt(recordIn.Blinding), zero)
	successor := spptest.MustNullifier(t, hostUtxoHash(t, recordOut), spptest.AsBigInt(recordOut.Blinding), zero)

	heads := spptest.NewHeadMap(t, HeadMapHeight)
	transition := heads.Transfer(t, heads.Register(t, member, spent).NewIndex, successor)

	elements := s.keys.ChainElements(t, s.privateTxHash)
	c.PublicInputHash = spptest.MustHashChain(t, append(elements,
		s.policyHash, s.stateRoot, s.nullifierRoot, big.NewInt(entriesTreeID),
		s.ringID, s.ownOwnerHash, new(big.Int).SetUint64(s.windowIndex), boolVar(s.approval),
		transition.OldRoot, transition.NewRoot,
	))

	assignment := &CompressedPolicyCircuit{
		Policy:      *c,
		HeadOldRoot: transition.OldRoot,
		HeadNewRoot: transition.NewRoot,
		HeadNext:    transition.Leaf.Next,
		HeadIndex:   transition.Index,
	}
	for i := range assignment.HeadProof {
		assignment.HeadProof[i] = transition.Proof[i]
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

func TestCompressedCircuitRejectsWrongNewRoot(t *testing.T) {
	assignment := compressedRoundTrip(t)
	assignment.HeadNewRoot = big.NewInt(0xbad)
	test.NewAssert(t).SolvingFailed(
		&CompressedPolicyCircuit{}, assignment, test.WithCurves(ecc.BN254),
	)
}
