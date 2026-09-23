package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/custom_rings/circuits/registry"
)

func (c *CustomRingPolicyCircuit) constrainOutputKeys(api frontend.API, txContext transactionContext) {
	registry.AssertMode(api, c.KeyEscrow, c.KeyRegistryRoot)
	for i, output := range txContext.outputs {
		// Only namespace-owned records skip the registry, their owner hash binds the zero nullifier key.
		namespace := api.IsZero(api.Sub(output.owner, c.NamespaceOwnerHash))
		cond := api.Mul(output.utxo, c.KeyEscrow, api.Sub(1, namespace))
		c.OutputKeys[i].AssertEscrowed(api, cond, c.KeyRegistryRoot, output.ownerPkHash, output.nullifierPk)
	}
}
