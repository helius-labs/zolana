package registry

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/spp/spptest"
)

func proofVars(proof []big.Int) []frontend.Variable {
	vars := make([]frontend.Variable, len(proof))
	for i := range proof {
		vars[i] = proof[i]
	}
	return vars
}

type insertionCircuit struct {
	OldRoot        frontend.Variable `gnark:",public"`
	RegisteredRoot frontend.Variable `gnark:",public"`

	LowMember, LowNext, LowKey, LowIndex frontend.Variable
	LowProof                             []frontend.Variable
	Member, Key, NewIndex                frontend.Variable
	NewProof                             []frontend.Variable
}

func (c *insertionCircuit) Define(api frontend.API) error {
	registered := Insertion{
		OldRoot:  c.OldRoot,
		Low:      Leaf{Member: c.LowMember, Next: c.LowNext, Key: c.LowKey},
		LowIndex: c.LowIndex,
		LowProof: c.LowProof,
		Member:   c.Member,
		Key:      c.Key,
		NewIndex: c.NewIndex,
		NewProof: c.NewProof,
	}.NewRoot(api)
	api.AssertIsEqual(registered, c.RegisteredRoot)
	return nil
}

func registrationCircuit() *insertionCircuit {
	return &insertionCircuit{
		LowProof: make([]frontend.Variable, Height),
		NewProof: make([]frontend.Variable, Height),
	}
}

func registrationAssignment(t *testing.T, member, key *big.Int) *insertionCircuit {
	t.Helper()
	insertion := spptest.NewKeyRegistryTree(t, Height).Register(t, member, key)
	return &insertionCircuit{
		OldRoot:        insertion.OldRoot,
		RegisteredRoot: insertion.NewRoot,
		LowMember:      insertion.Low.Member,
		LowNext:        insertion.Low.Next,
		LowKey:         insertion.Low.Key,
		LowIndex:       insertion.LowIndex,
		LowProof:       proofVars(insertion.LowProof),
		Member:         member,
		Key:            key,
		NewIndex:       insertion.NewIndex,
		NewProof:       proofVars(insertion.NewProof),
	}
}

// custom-rings/interface/src/state.rs KEY_REGISTRY_EMPTY_ROOT.
func TestSentinelRootMatchesProgram(t *testing.T) {
	const programEmptyRoot = "03a753cd12b351201070a629c59b9a162c53a1fd33a138cbd6be814bfcfe980e"
	if got := fmt.Sprintf("%064x", spptest.NewKeyRegistryTree(t, Height).Root()); got != programEmptyRoot {
		t.Fatalf("sentinel root %s, the program pins %s", got, programEmptyRoot)
	}
}

func TestInsertionRegisters(t *testing.T) {
	assignment := registrationAssignment(t, big.NewInt(0x1234), big.NewInt(0x5e))
	test.NewAssert(t).SolvingSucceeded(registrationCircuit(), assignment, test.WithCurves(ecc.BN254))
}

// The host roots stay consistent, only the ordering assertion refuses.
func TestInsertionRejectsMisorderedMember(t *testing.T) {
	cases := []struct {
		name   string
		member *big.Int
	}{
		{"member equal to the predecessor", big.NewInt(0)},
		{"member equal to the predecessor successor", spptest.KeyRegistrySentinelNext()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assignment := registrationAssignment(t, tc.member, big.NewInt(0x5e))
			test.NewAssert(t).SolvingFailed(registrationCircuit(), assignment, test.WithCurves(ecc.BN254))
		})
	}
}

func TestInsertionRejectsIndexAliases(t *testing.T) {
	for _, name := range []string{"predecessor", "insertion"} {
		t.Run(name, func(t *testing.T) {
			assignment := registrationAssignment(t, big.NewInt(0x1234), big.NewInt(0x5e))
			if err := test.IsSolved(registrationCircuit(), assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("valid index control failed: %v", err)
			}
			index := &assignment.LowIndex
			if name == "insertion" {
				index = &assignment.NewIndex
			}
			*index = new(big.Int).Add(new(big.Int).SetUint64((*index).(uint64)), new(big.Int).Lsh(big.NewInt(1), Height))
			if err := test.IsSolved(registrationCircuit(), assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("index alias above the tree capacity was accepted")
			}
		})
	}
}
