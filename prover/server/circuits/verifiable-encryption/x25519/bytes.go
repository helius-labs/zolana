package x25519

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
)

func bytePower(n int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(n)) }

// splitByte constrains both pieces and their exact integer recomposition.
func splitByte(api frontend.API, f *emfield.Field, v frontend.Variable, lowBits, totalBits int) (high, low frontend.Variable) {
	raw, e := api.Compiler().NewHint(splitByteHint, 2, v, lowBits)
	if e != nil {
		panic(e)
	}
	f.RangeChecker().Check(raw[0], totalBits-lowBits)
	f.RangeChecker().Check(raw[1], lowBits)
	api.AssertIsEqual(v, api.Add(api.Mul(raw[0], bytePower(lowBits)), raw[1]))
	return raw[0], raw[1]
}

// Each input segment already has its declared unsigned bound. Only segments
// crossing a field limb boundary require an additional constrained split.
func packSegments(api frontend.API, f *emfield.Field, values []frontend.Variable, widths []int) *emfield.Element {
	var limbs []frontend.Variable
	var bound []int
	var limb frontend.Variable = 0
	used := 0
	for i, value := range values {
		width := widths[i]
		available := f.Layout().LimbBits - used
		if width > available {
			high, low := splitByte(api, f, value, available, width)
			limb = api.Add(limb, api.Mul(low, bytePower(used)))
			limbs = append(limbs, limb)
			bound = append(bound, f.Layout().LimbBits)
			limb = high
			used = width - available
		} else {
			limb = api.Add(limb, api.Mul(value, bytePower(used)))
			used += width
			if used == f.Layout().LimbBits {
				limbs = append(limbs, limb)
				bound = append(bound, used)
				limb = 0
				used = 0
			}
		}
	}
	if used > 0 {
		limbs = append(limbs, limb)
		bound = append(bound, used)
	}
	return f.Bounded(limbs, bound)
}

func outputBytes(api frontend.API, f *emfield.Field, shared *emfield.Element) [32]frontend.Variable {
	in := append([]frontend.Variable{f.Layout().LimbBits}, shared.Limbs()...)
	raw, e := api.Compiler().NewHint(outputBytesHint, 32, in...)
	if e != nil {
		panic(e)
	}
	var out [32]frontend.Variable
	copy(out[:], raw)
	// Use the largest limb boundary below the native field capacity. One byte
	// crossing it is split; each equality then compares integers below 2^240.
	cut := min(240/f.Layout().LimbBits, len(shared.Limbs())-1)
	cutBits := cut * f.Layout().LimbBits
	byteCut, remaining := cutBits/8, cutBits%8
	for i := range out {
		if remaining == 0 || i != byteCut {
			width := 8
			if i == 31 {
				width = 7
			}
			f.RangeChecker().Check(out[i], width)
		}
	}
	lo, hi := frontend.Variable(0), frontend.Variable(0)
	for i := 0; i < byteCut; i++ {
		lo = api.Add(lo, api.Mul(out[i], bytePower(i*8)))
	}
	start := byteCut
	if remaining != 0 {
		high, low := splitByte(api, f, out[byteCut], remaining, 8)
		lo = api.Add(lo, api.Mul(low, bytePower(byteCut*8)))
		hi = high
		start++
	}
	for i := start; i < 32; i++ {
		hi = api.Add(hi, api.Mul(out[i], bytePower(i*8-cutBits)))
	}
	left, right := frontend.Variable(0), frontend.Variable(0)
	for i, v := range shared.Limbs() {
		if i < cut {
			left = api.Add(left, api.Mul(v, bytePower(i*f.Layout().LimbBits)))
		} else {
			right = api.Add(right, api.Mul(v, bytePower((i-cut)*f.Layout().LimbBits)))
		}
	}
	api.AssertIsEqual(left, lo)
	api.AssertIsEqual(right, hi)
	api.AssertIsDifferent(api.Add(0, 0, shared.Limbs()...), 0)
	return out
}

func init() { solver.RegisterHint(splitByteHint, outputBytesHint) }
func splitByteHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) != 2 || len(out) != 2 || !in[1].IsUint64() || in[1].Uint64() > 8 {
		return errors.New("byte split shape")
	}
	n := uint(in[1].Uint64())
	out[0].Rsh(in[0], n)
	out[1].And(in[0], new(big.Int).Sub(bytePower(int(n)), big.NewInt(1)))
	return nil
}
func outputBytesHint(_ *big.Int, in, out []*big.Int) error {
	if len(in) < 2 || len(out) != 32 || !in[0].IsUint64() || in[0].Uint64() > 128 {
		return errors.New("output byte shape")
	}
	value := new(big.Int)
	for i := len(in) - 1; i >= 1; i-- {
		value.Lsh(value, uint(in[0].Uint64())).Add(value, in[i])
	}
	for _, o := range out {
		o.And(value, big.NewInt(255))
		value.Rsh(value, 8)
	}
	return nil
}
