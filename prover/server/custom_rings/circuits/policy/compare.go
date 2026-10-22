package policy

import (
	"errors"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type comparator struct {
	rc frontend.Rangechecker
	// width bounds every difference the key compares, fixed when the key compiles.
	width int
}

// comparator sizes width for m outputs against one public net, each within the u64 SPP range checks.
func (p *Policy) comparator(rc frontend.Rangechecker) comparator {
	return comparator{rc: rc, width: shared.AmountBits + bits.Len(uint(len(p.Outputs)+1))}
}

// atMost returns total <= threshold, the caller bounds their difference below 2^width in magnitude.
func (c comparator) atMost(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	offset := new(big.Int).Lsh(big.NewInt(1), uint(c.width))
	delta := api.Add(api.Sub(threshold, total), offset)
	// 1. The hint proposes the low width bits and the top bit of delta, untrusted until the checks below bind them.
	parts, err := api.Compiler().NewHint(comparisonHint, 2, delta, c.width)
	if err != nil {
		panic(err)
	}
	low, top := parts[0], parts[1]
	// 2. low below 2^width leaves one split per delta.
	c.rc.Check(low, c.width)
	// 3. top is a bit, the split then covers delta below 2^(width+1) only.
	api.AssertIsBoolean(top)
	// 4. delta lies in (0, 2^(width+1)), its split is unique and top is set exactly when total <= threshold.
	api.AssertIsEqual(delta, api.Add(low, api.Mul(top, offset)))
	return top
}

func init() { solver.RegisterHint(comparisonHint) }

// comparisonHint splits delta at the width, atMost range checks and recomposes both parts.
func comparisonHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || !inputs[1].IsUint64() {
		return errors.New("comparison: want delta, width and two outputs")
	}
	width := uint(inputs[1].Uint64())
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
	outputs[0].And(inputs[0], mask)
	outputs[1].Rsh(inputs[0], width)
	return nil
}
