package policy

import (
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

type headRegistrationCircuit struct {
	OldRoot        frontend.Variable `gnark:",public"`
	RegisteredRoot frontend.Variable `gnark:",public"`

	LowMember, LowNext, LowNullifier, LowIndex frontend.Variable
	LowProof                                   []frontend.Variable
	Member, Genesis, NewIndex                  frontend.Variable
	NewProof                                   []frontend.Variable
}

func (c *headRegistrationCircuit) Define(api frontend.API) error {
	registered := headRegistration{
		oldRoot:  c.OldRoot,
		low:      headLeaf{member: c.LowMember, next: c.LowNext, nullifier: c.LowNullifier},
		lowIndex: c.LowIndex,
		lowProof: c.LowProof,
		member:   c.Member,
		genesis:  c.Genesis,
		newIndex: c.NewIndex,
		newProof: c.NewProof,
	}.newRoot(api)
	api.AssertIsEqual(registered, c.RegisteredRoot)
	return nil
}

func registrationCircuit() *headRegistrationCircuit {
	return &headRegistrationCircuit{
		LowProof: make([]frontend.Variable, HeadMapHeight),
		NewProof: make([]frontend.Variable, HeadMapHeight),
	}
}

func registrationAssignment(t *testing.T, member, genesis *big.Int) *headRegistrationCircuit {
	t.Helper()
	insertion := spptest.NewHeadMap(t, HeadMapHeight).Register(t, member, genesis)
	return &headRegistrationCircuit{
		OldRoot:        insertion.OldRoot,
		RegisteredRoot: insertion.NewRoot,
		LowMember:      insertion.Low.Member,
		LowNext:        insertion.Low.Next,
		LowNullifier:   insertion.Low.Nullifier,
		LowIndex:       insertion.LowIndex,
		LowProof:       proofVars(insertion.LowProof),
		Member:         member,
		Genesis:        genesis,
		NewIndex:       insertion.NewIndex,
		NewProof:       proofVars(insertion.NewProof),
	}
}

// custom-rings/interface/src/state.rs HEAD_MAP_EMPTY_ROOT.
func TestSentinelRootMatchesProgram(t *testing.T) {
	const programEmptyRoot = "03a753cd12b351201070a629c59b9a162c53a1fd33a138cbd6be814bfcfe980e"
	if got := hex32(spptest.NewHeadMap(t, HeadMapHeight).Root()); got != programEmptyRoot {
		t.Fatalf("sentinel root %s, the program pins %s", got, programEmptyRoot)
	}
}

func TestHeadMapRegisters(t *testing.T) {
	assignment := registrationAssignment(t, big.NewInt(0x1234), big.NewInt(0x5e))
	test.NewAssert(t).SolvingSucceeded(registrationCircuit(), assignment, test.WithCurves(ecc.BN254))
}

// The host roots stay consistent, only the ordering assertion refuses.
func TestHeadMapRejectsMisorderedRegistration(t *testing.T) {
	cases := []struct {
		name   string
		member *big.Int
	}{
		{"member equal to the predecessor", big.NewInt(0)},
		{"member equal to the predecessor successor", spptest.HeadMapSentinelNext()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assignment := registrationAssignment(t, tc.member, big.NewInt(0x5e))
			test.NewAssert(t).SolvingFailed(registrationCircuit(), assignment, test.WithCurves(ecc.BN254))
		})
	}
}

func TestHeadMapRejectsIndexAliases(t *testing.T) {
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
			*index = new(big.Int).Add(new(big.Int).SetUint64((*index).(uint64)), new(big.Int).Lsh(big.NewInt(1), HeadMapHeight))
			if err := test.IsSolved(registrationCircuit(), assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("index alias above the tree capacity was accepted")
			}
		})
	}
}
