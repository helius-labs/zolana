package policy

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

func init() { solver.RegisterHint(amountComparisonHint, shapedAmountComparisonHint) }

// amountAtMost uses the same integer offset as outputTotalAtMost. The operands
// are nonnegative. The width is 64 plus ceil(log2(maximum slot count)), so the
// transaction's bounded amounts cannot overflow it, including wider shapes.
// Only the top bit is consumed. Lookup range checks bound the remaining limb.
func (c *CustomRingPolicyCircuit) amountAtMost(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	if !c.specialized() {
		return outputTotalAtMost(api, total, threshold)
	}
	width, offset := amountSumBits, amountSumOffset
	hint := solver.Hint(amountComparisonHint)
	if c.Dynamic != nil {
		width = amountBits + bits.Len(uint(max(len(c.Dynamic.Inputs), len(c.Dynamic.Outputs))-1))
		offset = new(big.Int).Lsh(big.NewInt(1), uint(width))
		hint = shapedAmountComparisonHint
	}
	delta := api.Add(api.Sub(threshold, total), offset)
	args := []frontend.Variable{delta}
	if c.Dynamic != nil {
		args = append(args, width)
	}
	w, err := api.Compiler().NewHint(hint, 2, args...)
	if err != nil {
		panic(err)
	}
	rangecheck.New(api).Check(w[0], width)
	api.AssertIsBoolean(w[1])
	api.AssertIsEqual(delta, api.Add(w[0], api.Mul(offset, w[1])))
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

// The width is compile-time metadata, not a prover-selected bound.
func shapedAmountComparisonHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || !inputs[1].IsUint64() || inputs[1].Uint64() < 64 || inputs[1].Uint64() > 70 {
		return fmt.Errorf("invalid shaped comparison width")
	}
	width := uint(inputs[1].Uint64())
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
	outputs[0].And(inputs[0], mask)
	outputs[1].Rsh(inputs[0], width)
	return nil
}
