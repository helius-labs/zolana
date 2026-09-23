package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/custom_rings/circuits/registry"
)

func (c *CustomRingPolicyCircuit) constrainOutputKeys(api frontend.API, txContext transactionContext) {
	registry.AssertMode(api, c.KeyEscrow, c.KeyRegistryRoot)
	for i, output := range txContext.outputs {
		c.OutputKeys[i].AssertEscrowed(api, api.Mul(output.utxo, c.KeyEscrow), c.KeyRegistryRoot, output.ownerPkHash, output.nullifierPk)
	}
}
