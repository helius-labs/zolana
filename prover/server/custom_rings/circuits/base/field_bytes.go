package base

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

func init() { solver.RegisterHint(canonicalBytesHint) }

// canonicalBytes binds the unique big-endian encoding of a native field value.
// The two 128-bit gap limbs prove integer x + gap = q-1. Each equation is
// bounded below 2^129+1, well below q, so neither equation can wrap modulo q.
// This preserves canonicality without decomposing every byte into Boolean bits.
func canonicalBytes(api frontend.API, value frontend.Variable) []frontend.Variable {
	q := api.Compiler().Field()
	if q.BitLen() <= 130 || q.BitLen() > 256 {
		panic("canonical bytes requires a native field between 131 and 256 bits")
	}
	w, err := api.Compiler().NewHint(canonicalBytesHint, 35, value)
	if err != nil {
		panic(err)
	}
	rc := rangecheck.New(api)
	for _, b := range w[:32] {
		rc.Check(b, 8)
	}
	rc.Check(w[32], 128)
	rc.Check(w[33], 128)
	api.AssertIsBoolean(w[34])
	pack := func(bytes []frontend.Variable) frontend.Variable {
		var n frontend.Variable = 0
		for _, b := range bytes {
			n = api.Add(api.Mul(n, 256), b)
		}
		return n
	}
	hi, lo := pack(w[:16]), pack(w[16:32])
	base := new(big.Int).Lsh(big.NewInt(1), 128)
	mask := new(big.Int).Sub(new(big.Int).Set(base), big.NewInt(1))
	limit := new(big.Int).Sub(q, big.NewInt(1))
	limitLo := new(big.Int).And(limit, mask)
	limitHi := new(big.Int).Rsh(limit, 128)
	api.AssertIsEqual(api.Add(lo, w[32]), api.Add(limitLo, api.Mul(w[34], base)))
	api.AssertIsEqual(api.Add(hi, w[33], w[34]), limitHi)
	api.AssertIsEqual(api.Add(api.Mul(hi, base), lo), value)
	return w[:32]
}

func canonicalBytesHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) != 35 {
		return fmt.Errorf("canonical bytes: expected one input and 35 outputs")
	}
	var bytes [32]byte
	inputs[0].FillBytes(bytes[:])
	for i, b := range bytes {
		outputs[i].SetUint64(uint64(b))
	}
	gap := new(big.Int).Sub(q, big.NewInt(1))
	gap.Sub(gap, inputs[0])
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	outputs[32].And(gap, mask)
	outputs[33].Rsh(gap, 128)
	outputs[34].And(inputs[0], mask)
	outputs[34].Add(outputs[34], outputs[32]).Rsh(outputs[34], 128)
	return nil
}
