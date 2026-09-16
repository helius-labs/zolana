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

type headMapRoundTripCircuit struct {
	OldRoot         frontend.Variable `gnark:",public"`
	RegisteredRoot  frontend.Variable `gnark:",public"`
	TransferredRoot frontend.Variable `gnark:",public"`

	LowMember, LowNext, LowNullifier, LowIndex frontend.Variable
	LowProof                                   []frontend.Variable
	Member, Genesis, NewIndex                  frontend.Variable
	NewProof                                   []frontend.Variable

	Spent, Successor, TransferIndex frontend.Variable
	TransferProof                   []frontend.Variable
}

func (c *headMapRoundTripCircuit) Define(api frontend.API) error {
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
	// The member keeps the sentinel's successor pointer, only its nullifier moves.
	transferred := headTransition{
		oldRoot:   registered,
		leaf:      headLeaf{member: c.Member, next: c.LowNext, nullifier: c.Spent},
		successor: c.Successor,
		index:     c.TransferIndex,
		proof:     c.TransferProof,
	}.newRoot(api)
	api.AssertIsEqual(transferred, c.TransferredRoot)
	return nil
}

type headTransitionCircuit struct {
	OldRoot frontend.Variable `gnark:",public"`
	NewRoot frontend.Variable `gnark:",public"`

	Member, Next, Spent, Successor, Index frontend.Variable
	Proof                                 []frontend.Variable
}

func (c *headTransitionCircuit) Define(api frontend.API) error {
	newRoot := headTransition{
		oldRoot:   c.OldRoot,
		leaf:      headLeaf{member: c.Member, next: c.Next, nullifier: c.Spent},
		successor: c.Successor,
		index:     c.Index,
		proof:     c.Proof,
	}.newRoot(api)
	api.AssertIsEqual(newRoot, c.NewRoot)
	return nil
}

func roundTripCircuit() *headMapRoundTripCircuit {
	return &headMapRoundTripCircuit{
		LowProof:      make([]frontend.Variable, HeadMapHeight),
		NewProof:      make([]frontend.Variable, HeadMapHeight),
		TransferProof: make([]frontend.Variable, HeadMapHeight),
	}
}

func roundTripAssignment(t *testing.T, member, genesis, successor *big.Int) *headMapRoundTripCircuit {
	t.Helper()
	heads := spptest.NewHeadMap(t, HeadMapHeight)
	insertion := heads.Register(t, member, genesis)
	transition := heads.Transfer(t, insertion.NewIndex, successor)
	return &headMapRoundTripCircuit{
		OldRoot:         insertion.OldRoot,
		RegisteredRoot:  insertion.NewRoot,
		TransferredRoot: transition.NewRoot,
		LowMember:       insertion.Low.Member,
		LowNext:         insertion.Low.Next,
		LowNullifier:    insertion.Low.Nullifier,
		LowIndex:        insertion.LowIndex,
		LowProof:        proofVars(insertion.LowProof),
		Member:          member,
		Genesis:         genesis,
		NewIndex:        insertion.NewIndex,
		NewProof:        proofVars(insertion.NewProof),
		Spent:           genesis,
		Successor:       successor,
		TransferIndex:   transition.Index,
		TransferProof:   proofVars(transition.Proof),
	}
}

func transitionCircuit() *headTransitionCircuit {
	return &headTransitionCircuit{Proof: make([]frontend.Variable, HeadMapHeight)}
}

func transitionAssignment(transition spptest.HeadMapTransition, successor *big.Int) *headTransitionCircuit {
	return &headTransitionCircuit{
		OldRoot:   transition.OldRoot,
		NewRoot:   transition.NewRoot,
		Member:    transition.Leaf.Member,
		Next:      transition.Leaf.Next,
		Spent:     transition.Leaf.Nullifier,
		Successor: successor,
		Index:     transition.Index,
		Proof:     proofVars(transition.Proof),
	}
}

// custom-rings/interface/src/state.rs HEAD_MAP_EMPTY_ROOT.
func TestSentinelRootMatchesProgram(t *testing.T) {
	const programEmptyRoot = "03a753cd12b351201070a629c59b9a162c53a1fd33a138cbd6be814bfcfe980e"
	if got := hex32(spptest.NewHeadMap(t, HeadMapHeight).Root()); got != programEmptyRoot {
		t.Fatalf("sentinel root %s, the program pins %s", got, programEmptyRoot)
	}
}

func TestHeadMapRegisterThenTransfer(t *testing.T) {
	assignment := roundTripAssignment(t, big.NewInt(0x1234), big.NewInt(0x5e), big.NewInt(0x77))
	test.NewAssert(t).SolvingSucceeded(roundTripCircuit(), assignment, test.WithCurves(ecc.BN254))
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
			assignment := roundTripAssignment(t, tc.member, big.NewInt(0x5e), big.NewInt(0x77))
			test.NewAssert(t).SolvingFailed(roundTripCircuit(), assignment, test.WithCurves(ecc.BN254))
		})
	}
}

func TestHeadMapTransitionSolves(t *testing.T) {
	heads := spptest.NewHeadMap(t, HeadMapHeight)
	insertion := heads.Register(t, big.NewInt(0x1234), big.NewInt(0x5e))
	successor := big.NewInt(0x77)
	transition := heads.Transfer(t, insertion.NewIndex, successor)
	test.NewAssert(t).SolvingSucceeded(
		transitionCircuit(), transitionAssignment(transition, successor), test.WithCurves(ecc.BN254),
	)
}

func TestHeadMapRejectsTransitionOverTheSentinel(t *testing.T) {
	heads := spptest.NewHeadMap(t, HeadMapHeight)
	heads.Register(t, big.NewInt(0x1234), big.NewInt(0x5e))
	successor := big.NewInt(0x77)
	transition := heads.Transfer(t, 0, successor)
	test.NewAssert(t).SolvingFailed(
		transitionCircuit(), transitionAssignment(transition, successor), test.WithCurves(ecc.BN254),
	)
}

func TestHeadMapRejectsTransitionOffTheSpentNullifier(t *testing.T) {
	heads := spptest.NewHeadMap(t, HeadMapHeight)
	insertion := heads.Register(t, big.NewInt(0x1234), big.NewInt(0x5e))
	successor := big.NewInt(0x77)
	assignment := transitionAssignment(heads.Transfer(t, insertion.NewIndex, successor), successor)
	assignment.Spent = big.NewInt(0x5f)
	test.NewAssert(t).SolvingFailed(transitionCircuit(), assignment, test.WithCurves(ecc.BN254))
}

func TestHeadMapRejectsIndexAliases(t *testing.T) {
	for _, name := range []string{"predecessor", "insertion", "transfer"} {
		t.Run(name, func(t *testing.T) {
			assignment := roundTripAssignment(t, big.NewInt(0x1234), big.NewInt(0x5e), big.NewInt(0x77))
			if err := test.IsSolved(roundTripCircuit(), assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("valid index control failed: %v", err)
			}
			index := &assignment.LowIndex
			switch name {
			case "insertion":
				index = &assignment.NewIndex
			case "transfer":
				index = &assignment.TransferIndex
			}
			*index = new(big.Int).Add(new(big.Int).SetUint64((*index).(uint64)), new(big.Int).Lsh(big.NewInt(1), HeadMapHeight))
			if err := test.IsSolved(roundTripCircuit(), assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("index alias above the tree capacity was accepted")
			}
		})
	}
}
