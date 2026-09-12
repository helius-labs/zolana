// The compressed windowed-velocity rail, the base policy statement plus an
// in-circuit head-map transition standing in for the per-member on-chain head PDA.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// CompressedPolicyCircuit carries the head-map transition under its own key.
type CompressedPolicyCircuit struct {
	Policy CustomRingPolicyCircuit

	// Bound by the program to the live on-chain head-map root.
	HeadOldRoot frontend.Variable
	// The head-map root the program writes after the transfer.
	HeadNewRoot frontend.Variable
	// Successor pointer, held fixed across a transfer.
	HeadNext  frontend.Variable
	HeadIndex frontend.Variable
	HeadProof [HeadMapHeight]frontend.Variable
}

func (c *CompressedPolicyCircuit) Define(api frontend.API) error {
	chain, txContext := c.Policy.constrainPolicy(api)

	// Input 0 is the member, the velocity sender slot.
	member := txContext.inputs[0].ownerPkHash
	spent := recordEntryNullifier(api, txContext.inputs[:])
	successor := recordEntryNullifier(api, txContext.outputs[:])
	newRoot := headMapTransfer(
		api, c.HeadOldRoot, member, c.HeadNext, spent, successor, c.HeadIndex, c.HeadProof[:],
	)
	api.AssertIsEqual(newRoot, c.HeadNewRoot)

	chain = append(chain, c.HeadOldRoot, c.HeadNewRoot)
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

// recordEntryNullifier opens the record slot the flag selects, the nullifier
// secret fixed to 0 to match SPP's record spend.
func recordEntryNullifier(api frontend.API, slots []utxoView) frontend.Variable {
	leaf := frontend.Variable(0)
	blinding := frontend.Variable(0)
	for _, slot := range slots {
		leaf = api.Add(leaf, api.Mul(slot.record, slot.hash))
		blinding = api.Add(blinding, api.Mul(slot.record, slot.blinding))
	}
	return gadget.PoseidonHash(api, []frontend.Variable{leaf, blinding, frontend.Variable(0)})
}
