package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// Adds current-head authentication to the member's windowed policy proof.
type CompressedPolicyCircuit struct {
	Policy          CustomRingPolicyCircuit
	TransactionSalt [16]frontend.Variable

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
	for i := range c.TransactionSalt {
		api.AssertIsEqual(c.TransactionSalt[i], c.Policy.Salt[i])
	}
	// 1. Prove the member's windowed policy and record transition.
	api.AssertIsDifferent(c.Policy.WindowSlots, 0)
	chain, txContext, counters := c.Policy.constrainPolicyRail(api, memberRail)

	// 2. Replace the consumed record's head with its successor nullifier.
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

	// 3. Bind both head roots for the program's atomic compare-and-replace.
	disclosureHash, err := counters.seal(api, c.Policy.TxViewingSk, c.TransactionSalt)
	if err != nil {
		return err
	}
	chain = append(chain, c.HeadOldRoot, c.HeadNewRoot, disclosureHash)
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
