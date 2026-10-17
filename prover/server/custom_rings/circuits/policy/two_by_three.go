package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// TwoByThreeCircuit retains the full policy statement with a fixed transaction
// shape and mode. Separate keys make the compile-time specialization enforceable.
type TwoByThreeCircuit struct {
	Policy CustomRingPolicyCircuit
	// Anonymous and Delegate are key metadata, never prover-controlled wires.
	Anonymous            bool `gnark:"-"`
	Delegate             bool `gnark:"-"`
	RegistrySubtreeDepth int  `gnark:"-"`
}

func (c *TwoByThreeCircuit) Define(api frontend.API) error {
	c.Policy.FixedInputs = 2
	c.Policy.FixedOutputs = 3
	c.Policy.FixedMode = 1
	c.Policy.RegistrySubtreeDepth = c.RegistrySubtreeDepth
	if c.Anonymous {
		c.Policy.FixedMode = 2
	}
	rail := memberRail
	if c.Delegate {
		rail = delegateRail
	}
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, c.Policy.constrain(api, rail)))
	return nil
}
