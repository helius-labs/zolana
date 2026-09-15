package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

type CompressedPolicyCircuit struct {
	Policy CustomRingPolicyCircuit

	// Bound by the program to the live on-chain head-map root.
	HeadOldRoot frontend.Variable
	// The successor root commits atomically with the SPP transfer.
	HeadNewRoot frontend.Variable
	// Successor pointer, held fixed across a transfer.
	HeadNext  frontend.Variable
	HeadIndex frontend.Variable
	HeadProof [HeadMapHeight]frontend.Variable
}

func (c *CompressedPolicyCircuit) Define(api frontend.API) error {
	api.AssertIsDifferent(c.Policy.WindowSlots, 0)
	chain, txContext := c.Policy.constrainPolicyRail(api, memberRail)

	newRoot := headTransition{
		oldRoot: c.HeadOldRoot,
		leaf: headLeaf{
			member:    txContext.inputs[0].ownerPkHash,
			next:      c.HeadNext,
			nullifier: selectedRecordNullifier(api, txContext.inputs[:]),
		},
		successor: selectedRecordNullifier(api, txContext.outputs[:]),
		index:     c.HeadIndex,
		proof:     c.HeadProof[:],
	}.newRoot(api)
	api.AssertIsEqual(newRoot, c.HeadNewRoot)

	chain = append(chain, c.HeadOldRoot, c.HeadNewRoot)
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

// The selected record uses SPP's namespace nullifier secret of zero.
func selectedRecordNullifier(api frontend.API, slots []utxoView) frontend.Variable {
	leaf := frontend.Variable(0)
	blinding := frontend.Variable(0)
	for _, slot := range slots {
		leaf = api.Add(leaf, api.Mul(slot.record, slot.hash))
		blinding = api.Add(blinding, api.Mul(slot.record, slot.blinding))
	}
	return gadget.PoseidonHash(api, []frontend.Variable{leaf, blinding, frontend.Variable(0)})
}
