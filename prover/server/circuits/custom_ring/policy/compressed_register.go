// Proves one head-map insertion for the compressed velocity rail. Registration
// is program-authorized, so the program vouches for the member and its genesis
// nullifier, binds them and the append cursor into the public input, and
// advances the on-chain root by the returned HeadNewRoot.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// CompressedRegisterCircuit inserts a member off a low element and empty slot.
type CompressedRegisterCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	HeadOldRoot frontend.Variable
	HeadNewRoot frontend.Variable
	Member      frontend.Variable
	Genesis     frontend.Variable
	// The canonical append cursor, bound so Photon reproduces the position.
	NewIndex frontend.Variable

	LowMember    frontend.Variable
	LowNext      frontend.Variable
	LowNullifier frontend.Variable
	LowIndex     frontend.Variable
	LowProof     [HeadMapHeight]frontend.Variable
	NewProof     [HeadMapHeight]frontend.Variable
}

func (c *CompressedRegisterCircuit) Define(api frontend.API) error {
	newRoot := headMapRegister(
		api, c.HeadOldRoot,
		c.LowMember, c.LowNext, c.LowNullifier, c.LowIndex, c.LowProof[:],
		c.Member, c.Genesis, c.NewIndex, c.NewProof[:],
	)
	api.AssertIsEqual(newRoot, c.HeadNewRoot)

	chain := []frontend.Variable{c.HeadOldRoot, c.HeadNewRoot, c.Member, c.Genesis, c.NewIndex}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
