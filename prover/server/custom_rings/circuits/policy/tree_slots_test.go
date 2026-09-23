package policy

import (
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/spptest"
)

// Chain positions after the eleven audit elements.
const (
	chainTreeSlots             = 12
	chainAddressTreeID         = 13
	chainRevocationTreeIndexes = 20
)

// Rebinds the public input hash to a tampered program element, only the tamper can reject.
func rebind(t *testing.T, s *statement, c *CustomRingPolicyCircuit, facts []int, index int, value *big.Int) {
	t.Helper()
	elements := s.policyChainElements(t, facts)
	elements[index] = value
	c.PublicInputHash = spptest.MustHashChain(t, elements)
}

// Present in slot 1, unclaimed in the address tree, cleared in slot 2.
func spreadStatement(t *testing.T) (*statement, []int) {
	t.Helper()
	f := defaultFixture()
	s := newStatement(t, f)
	s.entries[allowedActive].slot = 1
	s.entries[blockedCleared].slot = 2
	s.deriveEntries(t)
	return s, f.listFacts
}

func TestListFactsReadTheirOwnSlots(t *testing.T) {
	s, facts := spreadStatement(t)
	if got := s.revocationTreeIndexes(facts); got.Cmp(big.NewInt(1+2<<6)) != 0 {
		t.Fatalf("packed revocation tree indexes %s", got)
	}
	solve(t, testConstraintSystem(t), s.assignment(t, facts))
}

func TestListFactsRejectWrongSlots(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*testing.T, *statement, []int) *CustomRingPolicyCircuit
	}{
		{"slot id differs from the entry's tree", func(t *testing.T, s *statement, facts []int) *CustomRingPolicyCircuit {
			c := s.assignment(t, facts)
			c.TreeSlots[1].ID = big.NewInt(addressTreeID + 5)
			slots := s.treeSlots(t)
			slots[1].ID = big.NewInt(addressTreeID + 5)
			rebind(t, s, c, facts, chainTreeSlots, spptest.MustTreeSlotsHashChain(t, slots))
			return c
		}},
		{"unclaimed address outside the address tree", func(t *testing.T, s *statement, facts []int) *CustomRingPolicyCircuit {
			s.entries[senderNotFrozen].slot = 1
			s.deriveEntries(t)
			return s.assignment(t, facts)
		}},
		{"unused slot selected", func(t *testing.T, s *statement, facts []int) *CustomRingPolicyCircuit {
			c := s.assignment(t, facts)
			c.ListFacts[0].TreeSlot = big.NewInt(3)
			rebind(t, s, c, facts, chainRevocationTreeIndexes, big.NewInt(3+2<<6))
			return c
		}},
		{"revocation tree index misreported", func(t *testing.T, s *statement, facts []int) *CustomRingPolicyCircuit {
			c := s.assignment(t, facts)
			rebind(t, s, c, facts, chainRevocationTreeIndexes, big.NewInt(2<<6))
			return c
		}},
		{"address tree id differs from the entry addresses", func(t *testing.T, s *statement, facts []int) *CustomRingPolicyCircuit {
			c := s.assignment(t, facts)
			c.AddressTreeID = big.NewInt(addressTreeID + 1)
			rebind(t, s, c, facts, chainAddressTreeID, big.NewInt(addressTreeID+1))
			return c
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, facts := spreadStatement(t)
			rejectAssignment(t, tt.tamper(t, s, facts))
		})
	}
}

// A disabled fact's slot neither selects a tree nor enters the packed indexes.
func TestDisabledListFactSlotIsFree(t *testing.T) {
	s, facts := spreadStatement(t)
	c := s.assignment(t, facts)
	c.ListFacts[3] = s.listFactForEntry(t, allowedNotBlocked)
	c.ListFacts[3].Enabled = big.NewInt(0)
	c.ListFacts[3].TreeSlot = big.NewInt(4)
	solve(t, testConstraintSystem(t), c)
}

func TestSpendRecordMovesAcrossTrees(t *testing.T) {
	f := velocityDefault()
	s := newStatement(t, f)
	s.inputs[len(s.inputs)-1].TreeID = big.NewInt(addressTreeID + 1)
	s.outputs[len(s.outputs)-1].TreeID = big.NewInt(addressTreeID + 2)
	solve(t, testConstraintSystem(t), s.assignment(t, f.facts()))
}

func TestSpendAddressHashesUnderTheAddressTree(t *testing.T) {
	f := velocityDefault()
	f.rulesFree = true
	s := newStatement(t, f)
	c := s.assignment(t, nil)
	c.AddressTreeID = big.NewInt(addressTreeID + 1)
	rebind(t, s, c, nil, chainAddressTreeID, big.NewInt(addressTreeID+1))
	rejectAssignment(t, c)
}
