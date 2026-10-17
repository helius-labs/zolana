package policy

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

func init() { solver.RegisterHint(amountComparisonHint) }

// amountAtMost uses the same integer offset as outputTotalAtMost. The operands
// are nonnegative and below 2^amountSumBits by the transaction and table checks.
// Only the top bit is consumed. Lookup range checks bound the remaining limb.
func (c *CustomRingPolicyCircuit) amountAtMost(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	if c.FixedInputs == 0 {
		return outputTotalAtMost(api, total, threshold)
	}
	delta := api.Add(api.Sub(threshold, total), amountSumOffset)
	w, err := api.Compiler().NewHint(amountComparisonHint, 2, delta)
	if err != nil {
		panic(err)
	}
	rangecheck.New(api).Check(w[0], amountSumBits)
	api.AssertIsBoolean(w[1])
	api.AssertIsEqual(delta, api.Add(w[0], api.Mul(amountSumOffset, w[1])))
	return w[1]
}

func amountComparisonHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) != 2 {
		return fmt.Errorf("amount comparison: expected 1 input and 2 outputs")
	}
	mask := new(big.Int).Sub(amountSumOffset, big.NewInt(1))
	outputs[0].And(inputs[0], mask)
	outputs[1].Rsh(inputs[0], uint(amountSumBits))
	return nil
}
