package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties: the windowed member policy holds, and its successor counters are sealed to the viewing key
// under the audit salt, their disclosure hash closing the chain as the program hashes it.

type CompressedPolicyCircuit struct {
	Policy CustomRingPolicyCircuit
}

func (c *CompressedPolicyCircuit) Define(api frontend.API) error {
	api.AssertIsDifferent(c.Policy.WindowSlots, 0)
	chain, counters := c.Policy.constrain(api, memberRail)
	disclosure, err := counters.seal(api, c.Policy.TxViewingSk, c.Policy.Salt)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Policy.PublicInputHash, gadget.HashChain(api, append(chain, disclosure)))
	return nil
}
