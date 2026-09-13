package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// CompressedRegisterCircuit proves insertion of a member's authorized genesis nullifier.
type CompressedRegisterCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	HeadOldRoot frontend.Variable
	HeadNewRoot frontend.Variable
	Member      frontend.Variable
	Genesis     frontend.Variable
	// Canonical append cursor, bound to fix the insertion position.
	NewIndex frontend.Variable

	LowMember    frontend.Variable
	LowNext      frontend.Variable
	LowNullifier frontend.Variable
	LowIndex     frontend.Variable
	LowProof     [HeadMapHeight]frontend.Variable
	NewProof     [HeadMapHeight]frontend.Variable
}

func (c *CompressedRegisterCircuit) Define(api frontend.API) error {
	// 1. Prove absence and insertion at the program's append cursor.
	newRoot := constrainHeadRegistration(
		api, c.HeadOldRoot,
		c.LowMember, c.LowNext, c.LowNullifier, c.LowIndex, c.LowProof[:],
		c.Member, c.Genesis, c.NewIndex, c.NewProof[:],
	)
	api.AssertIsEqual(newRoot, c.HeadNewRoot)

	// 2. Bind the insertion to the member and genesis validated by the program.
	chain := []frontend.Variable{c.HeadOldRoot, c.HeadNewRoot, c.Member, c.Genesis, c.NewIndex}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
