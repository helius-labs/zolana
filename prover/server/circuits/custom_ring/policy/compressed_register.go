package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

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
	newRoot := headRegistration{
		oldRoot:  c.HeadOldRoot,
		low:      headLeaf{member: c.LowMember, next: c.LowNext, nullifier: c.LowNullifier},
		lowIndex: c.LowIndex,
		lowProof: c.LowProof[:],
		member:   c.Member,
		genesis:  c.Genesis,
		newIndex: c.NewIndex,
		newProof: c.NewProof[:],
	}.newRoot(api)
	api.AssertIsEqual(newRoot, c.HeadNewRoot)

	chain := []frontend.Variable{c.HeadOldRoot, c.HeadNewRoot, c.Member, c.Genesis, c.NewIndex}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
