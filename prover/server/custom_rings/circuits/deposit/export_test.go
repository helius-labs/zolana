package deposit

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

func Statement(api frontend.API, c *CustomRingDepositCircuit, count base.Count, commitments []frontend.Variable, sealed base.Sealed) []frontend.Variable {
	return c.statement(api, count, commitments, sealed)
}
