package policy

import (
	"github.com/consensys/gnark/frontend"
	"zolana/prover/circuits/gadget"
)

// CustomRingDelegatePolicyCircuit proves audit and list rules without member outflow limits.
type CustomRingDelegatePolicyCircuit struct {
	Policy CustomRingPolicyCircuit
}

func (c *CustomRingDelegatePolicyCircuit) Define(api frontend.API) error {
	// 1. Apply the exemption fixed by the delegate instruction's verifying key.
	chain, _ := c.Policy.constrainPolicyRail(api, true)
	// 2. Bind the full policy commitment despite the velocity exemption.
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
