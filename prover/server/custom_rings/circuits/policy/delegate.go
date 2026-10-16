package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties: the policy rail without outflow limits, it still commits the rows,
// needs no approval and escrows every key.

type CustomRingDelegatePolicyCircuit struct {
	Policy CustomRingPolicyCircuit
}

func (c *CustomRingDelegatePolicyCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, c.Policy.constrain(api, delegateRail)))
	return nil
}
