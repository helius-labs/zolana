package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

type CustomRingDelegatePolicyCircuit struct {
	Policy CustomRingPolicyCircuit
}

func (c *CustomRingDelegatePolicyCircuit) Define(api frontend.API) error {
	chain, _ := c.Policy.constrainPolicyRail(api, delegateRail)
	// The exempt rail still commits the velocity rows.
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
