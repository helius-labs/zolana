package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/spp/spptest"
)

func compressedAssignment(t *testing.T, chain func(policy []*big.Int, disclosure *big.Int) []*big.Int) *CompressedPolicyCircuit {
	t.Helper()
	f := velocityDefault()
	s := newStatement(t, f)
	c := s.assignment(t, f.facts())

	var secret [32]byte
	for i, b := range c.TxViewingSk {
		secret[i] = byte(spptest.AsBigInt(b).Uint64())
	}
	elements := s.auditChainElements(t)
	elements = append(elements,
		s.policyHash, s.stateRoot, s.nullifierRoot, big.NewInt(entriesTreeID),
		s.ringID, s.ownOwnerHash, new(big.Int).SetUint64(s.windowIndex), boolVar(s.approval),
	)
	elements = append(elements, s.revocationTargets(f.facts())...)
	disclosure := spptest.CounterDisclosure{
		Secret: secret, CounterSalt: s.record.nextSalt, Assets: s.record.assets, Spent: s.record.nextSpent,
	}.Hash(t)
	c.PublicInputHash = spptest.MustHashChain(t, chain(elements, disclosure))

	assignment := &CompressedPolicyCircuit{Policy: *c}
	for i := range assignment.TransactionSalt {
		assignment.TransactionSalt[i] = 0
	}
	return assignment
}

// The program hashes the policy elements, then the counters disclosure hash.
func programChain(policy []*big.Int, disclosure *big.Int) []*big.Int {
	return append(policy, disclosure)
}

func TestCompressedCircuitSolves(t *testing.T) {
	test.NewAssert(t).SolvingSucceeded(
		&CompressedPolicyCircuit{}, compressedAssignment(t, programChain), test.WithCurves(ecc.BN254),
	)
}

func TestCompressedCircuitBindsTransactionSalt(t *testing.T) {
	assignment := compressedAssignment(t, programChain)
	assignment.TransactionSalt[0] = 1
	test.NewAssert(t).SolvingFailed(
		&CompressedPolicyCircuit{}, assignment, test.WithCurves(ecc.BN254),
	)
}

func TestCompressedCircuitRejectsReorderedChain(t *testing.T) {
	assignment := compressedAssignment(t, func(policy []*big.Int, disclosure *big.Int) []*big.Int {
		return append([]*big.Int{disclosure}, policy...)
	})
	test.NewAssert(t).SolvingFailed(
		&CompressedPolicyCircuit{}, assignment, test.WithCurves(ecc.BN254),
	)
}
