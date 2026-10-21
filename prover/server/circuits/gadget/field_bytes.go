package gadget

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() { solver.RegisterHint(fieldBytesHint) }

// FieldToBytesBEWith is FieldToBytesBE through rc, both gap equations stay under 2^129 + 1 and cannot wrap modulo q.
func FieldToBytesBEWith(api frontend.API, rc frontend.Rangechecker, value frontend.Variable) [32]frontend.Variable {
	q := api.Compiler().Field()
	if q.BitLen() <= 130 || q.BitLen() > 256 {
		panic("field to bytes with: native field outside 131 to 256 bits")
	}
	w, err := api.Compiler().NewHint(fieldBytesHint, 35, value)
	if err != nil {
		panic(err)
	}
	bytes, gapLo, gapHi, carry := w[:32], w[32], w[33], w[34]
	// 1. The hint's bytes are bytes, both gap limbs fit 128 bits and the carry is a bit.
	for _, b := range bytes {
		rc.Check(b, byteBits)
	}
	rc.Check(gapLo, 128)
	rc.Check(gapHi, 128)
	api.AssertIsBoolean(carry)
	pack := func(bytes []frontend.Variable) frontend.Variable {
		n := frontend.Variable(0)
		for _, b := range bytes {
			n = api.Add(api.Mul(n, 256), b)
		}
		return n
	}
	hi, lo := pack(bytes[:16]), pack(bytes[16:])
	base := new(big.Int).Lsh(big.NewInt(1), 128)
	limit := new(big.Int).Sub(q, big.NewInt(1))
	limitLo := new(big.Int).And(limit, new(big.Int).Sub(base, big.NewInt(1)))
	limitHi := new(big.Int).Rsh(limit, 128)
	// 2. The bytes plus the gap add up to q-1 without a wrap, so they encode an integer below q.
	api.AssertIsEqual(api.Add(lo, gapLo), api.Add(limitLo, api.Mul(carry, base)))
	api.AssertIsEqual(api.Add(hi, gapHi, carry), limitHi)
	// 3. The bytes recompose to value, the one encoding below q.
	api.AssertIsEqual(api.Add(api.Mul(hi, base), lo), value)
	return [32]frontend.Variable(bytes)
}

// fieldBytesHint proposes the bytes, gap limbs and carry of a value, untrusted until FieldToBytesBEWith range-checks and recomposes them.
func fieldBytesHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) != 35 {
		return errors.New("field bytes: expected one input and 35 outputs")
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
