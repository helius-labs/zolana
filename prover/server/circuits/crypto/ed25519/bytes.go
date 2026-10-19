package ed25519

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

// Split a limb into bounded low bits and a bounded quotient. Recomposition
// fits below the native modulus, so the output is the actual integer suffix.
func (c *curve) lowBits(v frontend.Variable, n int) []frontend.Variable {
	out, err := c.api.Compiler().NewHint(lowSplitHint, 2, v, n)
	if err != nil {
		panic(err)
	}
	bits := c.api.ToBinary(out[0], n)
	c.fp.RangeChecker().Check(out[1], layout.LimbBits-n)
	c.api.AssertIsEqual(v, c.api.Add(out[0], c.api.Mul(out[1], pow2(n))))
	return bits
}

// Registers untrusted witness hints. Their callers enforce the required relations.
func init() { solver.RegisterHint(lowSplitHint, byteLimbsHint) }

// Suggest a bit split. Each consumer constrains both parts and reconstruction.
func lowSplitHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) != 2 || len(out) != 2 || !in[1].IsUint64() || in[1].Uint64() > 128 {
		return errors.New("low split shape")
	}
	n := uint(in[1].Uint64())
	out[0].And(in[0], new(big.Int).Sub(pow2(int(n)), big.NewInt(1)))
	out[1].Rsh(in[0], n)
	return nil
}

// byteElement re-limbs little-endian bytes with bounded carries. A join spans at
// most two limbs plus 7 bits, below BN254, so field equality is integer equality.
func (c *curve) byteElement(f *nonnative.Field, data []frontend.Variable, totalBits int) *nonnative.Element {
	if len(data) != (totalBits+7)/8 {
		panic("ed25519: byte layout length")
	}
	rc := c.fp.RangeChecker()
	for i, b := range data {
		rc.Check(b, min(8, totalBits-8*i))
	}
	n := (totalBits + layout.LimbBits - 1) / layout.LimbBits
	groups := (n + 1) / 2
	raw, err := c.api.Compiler().NewHint(byteLimbsHint, n+groups, append([]frontend.Variable{layout.LimbBits, totalBits}, data...)...)
	if err != nil {
		panic(err)
	}
	limbs, widths := raw[:n], make([]int, n)
	for i, l := range limbs {
		widths[i] = min(layout.LimbBits, totalBits-layout.LimbBits*i)
		rc.Check(l, widths[i])
	}
	consumed, remaining := 0, 0
	carry := frontend.Variable(0)
	for start, g := 0, 0; start < n; start, g = start+2, g+1 {
		end := min(start+2, n)
		outBits := 0
		packed := frontend.Variable(0)
		for i := start; i < end; i++ {
			packed = c.api.Add(packed, c.api.Mul(limbs[i], pow2(outBits)))
			outBits += widths[i]
		}
		count := max(0, (outBits-remaining+7)/8)
		value := frontend.Variable(0)
		for i := 0; i < count; i++ {
			value = c.api.Add(value, c.api.Mul(data[consumed+i], pow2(8*i)))
		}
		value = c.api.Add(carry, c.api.Mul(value, pow2(remaining)))
		remaining += 8*count - outBits
		next := raw[n+g]
		if end == n {
			c.api.AssertIsEqual(next, 0)
		} else {
			rc.Check(next, remaining)
		}
		c.api.AssertIsEqual(value, c.api.Add(packed, c.api.Mul(next, pow2(outBits))))
		consumed += count
		carry = next
	}
	if consumed != len(data) {
		panic("ed25519: byte layout leaves bytes unbound")
	}
	return f.Bounded(limbs, widths)
}

// Suggest limb/carry witnesses. byteElement bounds and joins every piece.
func byteLimbsHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) < 2 || !in[0].IsUint64() || !in[1].IsUint64() {
		return errors.New("byte limbs header")
	}
	bits, total := int(in[0].Uint64()), int(in[1].Uint64())
	if bits < 1 || bits > 128 || total < 1 || total > 512 || len(in) != 2+(total+7)/8 {
		return errors.New("byte limbs shape")
	}
	n := (total + bits - 1) / bits
	if len(out) != n+(n+1)/2 {
		return errors.New("byte limbs outputs")
	}
	v := new(big.Int)
	for i := len(in) - 1; i >= 2; i-- {
		v.Lsh(v, 8).Add(v, in[i])
	}
	for i := 0; i < n; i++ {
		w := min(bits, total-i*bits)
		out[i].And(new(big.Int).Rsh(new(big.Int).Set(v), uint(i*bits)), new(big.Int).Sub(pow2(w), big.NewInt(1)))
	}
	for start, g := 0, 0; start < n; start, g = start+2, g+1 {
		end := min((start+2)*bits, total)
		extra := (end+7)/8*8 - end
		out[n+g].And(new(big.Int).Rsh(new(big.Int).Set(v), uint(end)), new(big.Int).Sub(pow2(extra), big.NewInt(1)))
	}
	return nil
}
