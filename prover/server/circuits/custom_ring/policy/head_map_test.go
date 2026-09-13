package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/iden3/go-iden3-crypto/poseidon"

	merkletree "zolana/prover/merkle-tree"
)

func headLeafValue(member, next, nullifier *big.Int) big.Int {
	hash, err := poseidon.Hash([]*big.Int{member, next, nullifier})
	if err != nil {
		panic(err)
	}
	return *hash
}

func proofVars(proof []big.Int) []frontend.Variable {
	vars := make([]frontend.Variable, len(proof))
	for i := range proof {
		vars[i] = proof[i]
	}
	return vars
}

// headMapRoundTripCircuit checks registration and transition against host tree roots.
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
	registered := constrainHeadRegistration(api, c.OldRoot,
		c.LowMember, c.LowNext, c.LowNullifier, c.LowIndex, c.LowProof,
		c.Member, c.Genesis, c.NewIndex, c.NewProof)
	api.AssertIsEqual(registered, c.RegisteredRoot)
	// The member keeps the sentinel's successor pointer, only its nullifier moves.
	transferred := constrainHeadTransition(api, registered,
		c.Member, c.LowNext, c.Spent, c.Successor, c.TransferIndex, c.TransferProof)
	api.AssertIsEqual(transferred, c.TransferredRoot)
	return nil
}

func TestHeadMapRegisterThenTransfer(t *testing.T) {
	pMinusOne := new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
	zero := big.NewInt(0)
	member := big.NewInt(0x1234)
	genesis := big.NewInt(0x5e)
	successor := big.NewInt(0x77)

	tree := merkletree.NewTree(HeadMapHeight)
	sentinel := headLeafValue(zero, pMinusOne, zero)
	tree.Update(0, sentinel)
	oldRoot := tree.Root.Value()

	lowProof := tree.GenerateProof(0)
	spliced := headLeafValue(zero, member, zero)
	tree.Update(0, spliced)
	newProof := tree.GenerateProof(1)
	memberLeaf := headLeafValue(member, pMinusOne, genesis)
	tree.Update(1, memberLeaf)
	registeredRoot := tree.Root.Value()

	transferProof := tree.GenerateProof(1)
	tree.Update(1, headLeafValue(member, pMinusOne, successor))
	transferredRoot := tree.Root.Value()

	assignment := &headMapRoundTripCircuit{
		OldRoot:         oldRoot,
		RegisteredRoot:  registeredRoot,
		TransferredRoot: transferredRoot,
		LowMember:       zero,
		LowNext:         pMinusOne,
		LowNullifier:    zero,
		LowIndex:        0,
		LowProof:        proofVars(lowProof),
		Member:          member,
		Genesis:         genesis,
		NewIndex:        1,
		NewProof:        proofVars(newProof),
		Spent:           genesis,
		Successor:       successor,
		TransferIndex:   1,
		TransferProof:   proofVars(transferProof),
	}
	circuit := &headMapRoundTripCircuit{
		LowProof:      make([]frontend.Variable, HeadMapHeight),
		NewProof:      make([]frontend.Variable, HeadMapHeight),
		TransferProof: make([]frontend.Variable, HeadMapHeight),
	}
	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}
