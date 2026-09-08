package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

func TestListFactBranches(t *testing.T) {
	tests := []struct {
		name       string
		entryIndex int
		mode       int64
	}{
		{"present", allowedActive, ModePresent},
		{"cleared", blockedCleared, ModeAbsent},
		{"never created", allowedNotBlocked, ModeAbsent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStatement(t, defaultFixture())
			entry := s.entries[tt.entryIndex]
			s.rules = []rule{{subject: SubjectOutputOwner, mode: tt.mode, mask: listMask(entry.listId)}}
			s.inlineAssets = nil
			s.outputs[0].OwnerPkHash = entry.member
			solve(t, testConstraintSystem(t), s.assignment(t, []int{tt.entryIndex}))
		})
	}
}

func TestListFactRequiresStrictNullifierInterval(t *testing.T) {
	tests := []struct {
		name   string
		bounds func(target, modulus *big.Int) (*big.Int, *big.Int)
		passes bool
	}{
		{"lower endpoint", func(target, modulus *big.Int) (*big.Int, *big.Int) {
			return target, new(big.Int).Sub(modulus, big.NewInt(1))
		}, false},
		{"upper endpoint", func(target, modulus *big.Int) (*big.Int, *big.Int) {
			return big.NewInt(0), target
		}, false},
		{"reversed interval", func(target, modulus *big.Int) (*big.Int, *big.Int) {
			return new(big.Int).Add(target, big.NewInt(1)), new(big.Int).Sub(target, big.NewInt(1))
		}, false},
		{"interval near modulus", func(target, modulus *big.Int) (*big.Int, *big.Int) {
			return new(big.Int).Sub(modulus, big.NewInt(2)), new(big.Int).Sub(modulus, big.NewInt(1))
		}, false},
		{"full field interval", func(target, modulus *big.Int) (*big.Int, *big.Int) {
			return big.NewInt(0), new(big.Int).Sub(modulus, big.NewInt(1))
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStatement(t, defaultFixture())
			s.rules = []rule{{subject: SubjectOutputOwner, mode: ModePresent, mask: listMask(listAllow)}}
			s.inlineAssets = nil
			fact := s.listFactForEntry(t, allowedActive)
			low, next := tt.bounds(s.derived[allowedActive].nullifier, ecc.BN254.ScalarField())
			proof := s.nonInclusion[allowedActive]
			leaf := spptest.MustPoseidon(t, 3, []*big.Int{low, next})
			root, err := protocol.MerkleRoot(leaf, proof.PathElements, proof.LowIndex)
			if err != nil {
				t.Fatal(err)
			}
			s.nullifierRoot = root
			c := s.assignment(t, nil)
			fact.NullifierLowValue = low
			fact.NullifierNextValue = next
			c.ListFacts[0] = fact
			if tt.passes {
				solve(t, testConstraintSystem(t), c)
			} else {
				rejectAssignment(t, c)
			}
		})
	}
}
