package x25519

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/shortladder"
)

var bytePower = shortladder.Pow2

// splitByte decomposes a value into bounded high and low pieces.
// The caller supplies 0 < lowBits < totalBits <= 8. Both pieces are checked,
// so recomposition is an integer equality and also bounds the original byte.
func splitByte(api frontend.API, f *emfield.Field, v frontend.Variable, lowBits, totalBits int) (high, low frontend.Variable) {
	// 1. Obtain candidate pieces without trusting the solver.
	raw, e := api.Compiler().NewHint(splitByteHint, 2, v, lowBits)
	if e != nil {
		panic(e)
	}
	// 2. Bound both pieces and require exact recomposition of the input.
	f.RangeChecker().Check(raw[0], totalBits-lowBits)
	f.RangeChecker().Check(raw[1], lowBits)
	api.AssertIsEqual(v, api.Add(api.Mul(raw[0], bytePower(lowBits)), raw[1]))
	return raw[0], raw[1]
}

// packSegments packs little-endian segments into emulated limbs.
// Each segment must already have its declared unsigned bound of at most eight
// bits. Bounded records those proven bounds without adding range constraints.
// Segments crossing a limb boundary receive an additional constrained split.
func packSegments(api frontend.API, f *emfield.Field, values []frontend.Variable, widths []int) *emfield.Element {
	var limbs []frontend.Variable
	var bound []int
	var limb frontend.Variable = 0
	used := 0
	// 1. Fill limbs from bounded segments, splitting boundary crossings.
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
	// 2. Retain the partial top limb and record only bounds already proved.
	if used > 0 {
		limbs = append(limbs, limb)
		bound = append(bound, used)
	}
	return f.Bounded(limbs, bound)
}

// outputBytes encodes a canonical, reduced field element as 32 little-endian
// bytes and rejects zero DH. The caller must first assert canonicality.
// Two bounded recomposition equations bind every hinted byte without native
// field wraparound, so neither truncation nor an alternative encoding is free.
func outputBytes(api frontend.API, f *emfield.Field, shared *emfield.Element) [32]frontend.Variable {
	// 1. Obtain candidate bytes from the untrusted encoding hint.
	in := append([]frontend.Variable{f.Layout().LimbBits}, shared.Limbs()...)
	raw, e := api.Compiler().NewHint(outputBytesHint, 32, in...)
	if e != nil {
		panic(e)
	}
	var out [32]frontend.Variable
	copy(out[:], raw)
	// Use the largest limb boundary below the native field capacity. One byte
	// crossing it is split. Each equality then compares integers below 2^240.
	// 2. Bound the bytes and choose two chunks that each fit below 2^240.
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
	// 3. Recompose the byte chunks, splitting the byte crossing the limb cut.
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
	// 4. Recompose the same chunks from limbs and bind both equalities.
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
	// 5. Reject zero using nonnegative limbs whose sum cannot wrap in BN254 Fr.
	api.AssertIsDifferent(api.Add(0, 0, shared.Limbs()...), 0)
	return out
}

// init registers byte witnesses with the solver. Registration provides no
// soundness guarantee, which comes from the consuming circuit constraints.
func init() { solver.RegisterHint(splitByteHint, outputBytesHint) }

// splitByteHint proposes high and low pieces for the prover. Its outputs are
// untrusted and are range-checked and recomposed by splitByte.
func splitByteHint(_ *big.Int, in, out []*big.Int) error {
	// 1. Check the solver interface shape before reading its public split width.
	if len(in) != 2 || len(out) != 2 || !in[1].IsUint64() || in[1].Uint64() > 8 {
		return errors.New("byte split shape")
	}
	// 2. Propose the quotient and remainder, which splitByte checks in circuit.
	n := uint(in[1].Uint64())
	out[0].Rsh(in[0], n)
	out[1].And(in[0], new(big.Int).Sub(bytePower(int(n)), big.NewInt(1)))
	return nil
}

// outputBytesHint proposes a little-endian encoding for the prover. Its outputs
// are untrusted and are range-checked and bound to the input by outputBytes.
func outputBytesHint(_ *big.Int, in, out []*big.Int) error {
	// 1. Check the hint interface and public limb width.
	if len(in) < 2 || len(out) != 32 || !in[0].IsUint64() || in[0].Uint64() > 128 {
		return errors.New("output byte shape")
	}
	// 2. Reconstruct the host integer and extract its low 32 bytes.
	// outputBytes rejects any truncation through bounded recomposition.
	value := shortladder.Integer(in[1:], int(in[0].Uint64()))
	for _, o := range out {
		o.And(value, big.NewInt(255))
		value.Rsh(value, 8)
	}
	return nil
}
