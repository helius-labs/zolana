package policy

import (
	"github.com/consensys/gnark/frontend"
	"zolana/prover/circuits/gadget"
)

// Only the delegate instruction may select the velocity exemption key.
type CustomRingDelegatePolicyCircuit struct {
	Policy CustomRingPolicyCircuit
}

func (c *CustomRingDelegatePolicyCircuit) Define(api frontend.API) error {
	chain, _ := c.Policy.constrainPolicyRail(api, true)
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
