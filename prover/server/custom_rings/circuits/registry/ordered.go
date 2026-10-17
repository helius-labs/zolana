package registry

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

func init() { solver.RegisterHint(orderedGapsHint) }

// assertOrderedWhen proves lo < mid < hi over canonical field integers.
// Four nonnegative integers partition q-1:
// lo + (mid-lo-1) + (hi-mid-1) + (q-1-hi) + 2 = q-1.
// Each is split into two bounded 128-bit limbs. The two sum equations are
// below 2^131, so they hold over integers, not just modulo q. The partition
// also proves every reconstructed value is canonical. No operand needs a
// full bit decomposition or a separate canonicality proof.
func assertOrderedWhen(api frontend.API, enabled, lo, mid, hi frontend.Variable) {
	q := api.Compiler().Field()
	if q.BitLen() <= 131 || q.BitLen() > 256 {
		panic("registry ordering requires a native field between 132 and 256 bits")
	}
	api.AssertIsBoolean(enabled)
	lo = api.Mul(enabled, lo)
	mid = api.Select(enabled, mid, 1)
	hi = api.Select(enabled, hi, 2)
	w, err := api.Compiler().NewHint(orderedGapsHint, 9, lo, mid, hi)
	if err != nil {
		panic(err)
	}
	rc := rangecheck.New(api)
	for _, limb := range w[:8] {
		rc.Check(limb, 128)
	}
	rc.Check(w[8], 2)
	base := new(big.Int).Lsh(big.NewInt(1), 128)
	mask := new(big.Int).Sub(new(big.Int).Set(base), big.NewInt(1))
	limit := new(big.Int).Sub(q, big.NewInt(1))
	low := new(big.Int).And(new(big.Int).Set(limit), mask)
	high := new(big.Int).Rsh(new(big.Int).Set(limit), 128)
	api.AssertIsEqual(api.Add(w[0], w[2], w[4], w[6], 2), api.Add(low, api.Mul(base, w[8])))
	api.AssertIsEqual(api.Add(w[1], w[3], w[5], w[7], w[8]), high)
	join := func(i int) frontend.Variable { return api.Add(w[i], api.Mul(base, w[i+1])) }
	api.AssertIsEqual(join(0), lo)
	api.AssertIsEqual(api.Add(lo, join(2), 1), mid)
	api.AssertIsEqual(api.Add(mid, join(4), 1), hi)
}

func orderedGapsHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 || len(outputs) != 9 {
		return fmt.Errorf("ordered gaps: expected 3 inputs and 9 outputs")
	}
	values := []*big.Int{
		new(big.Int).Set(inputs[0]),
		new(big.Int).Sub(new(big.Int).Sub(inputs[1], inputs[0]), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Sub(inputs[2], inputs[1]), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Sub(q, big.NewInt(1)), inputs[2]),
	}
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	carry := big.NewInt(2)
	for i, value := range values {
		if value.Sign() < 0 {
			value.SetInt64(0)
		}
		outputs[2*i].And(value, mask)
		outputs[2*i+1].Rsh(value, 128)
		carry.Add(carry, outputs[2*i])
	}
	outputs[8].Rsh(carry, 128)
	return nil
}
