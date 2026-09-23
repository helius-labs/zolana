package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

type CompressedPolicyCircuit struct {
	Policy          CustomRingPolicyCircuit
	TransactionSalt [16]frontend.Variable
}

func (c *CompressedPolicyCircuit) Define(api frontend.API) error {
	for i := range c.TransactionSalt {
		api.AssertIsEqual(c.TransactionSalt[i], c.Policy.Salt[i])
	}
	// 1. Prove the member's windowed policy and record transition.
	api.AssertIsDifferent(c.Policy.WindowSlots, 0)
	chain, counters := c.Policy.constrainPolicyRail(api, memberRail)

	// 2. The disclosure hash follows the policy chain, as the program hashes it.
	disclosureHash, err := counters.seal(api, c.Policy.TxViewingSk, c.TransactionSalt)
	if err != nil {
		return err
	}
	chain = append(chain, disclosureHash)
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
