package gadget

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// Full-field less-than comparison.
//
// The nullifier tree accepts any canonical field element (init sentinel p-1,
// insertable domain 0 < v < p-1), so ordering proofs compare full field values.
// A single 2^N-offset decomposition is unsound here: for a near p the offset
// sum a + 2^N - b wraps mod p and a false "a < b" decomposes cleanly, forging
// non-inclusion. Instead each operand is decomposed canonically once and
// compared as two bounded limbs.

// fieldLimbs is a field element split at the bit midpoint into two bounded
// limbs. Built only by CanonicalLimbs, which pins the decomposition.
type fieldLimbs struct {
	lo, hi         frontend.Variable
	loBits, hiBits int
}

// CanonicalLimbs decomposes x with the full-width ToBinary and returns the two
// halves. The full width is load-bearing: it constrains the bits to x's
// canonical (< p) value, so x and x+p cannot present different limbs. Don't
// pass a smaller NbDigits; it drops the < p check. Pinned by
// TestFullFieldCompareRejectsAliasBits.
func CanonicalLimbs(api frontend.API, x frontend.Variable) fieldLimbs {
	bits := api.ToBinary(x)
	half := len(bits) / 2
	return fieldLimbs{
		lo:     api.FromBinary(bits[:half]...),
		hi:     api.FromBinary(bits[half:]...),
		loBits: half,
		hiBits: len(bits) - half,
	}
}

// isLessBounded returns 1 iff x < y, for x, y < 2^k. The offset sum
// x - y + 2^k lies in (0, 2^(k+1)) — far below p for limb-sized k, so it
// cannot wrap — and its top bit is exactly x >= y.
func isLessBounded(api frontend.API, x, y frontend.Variable, k int) frontend.Variable {
	offset := new(big.Int).Lsh(big.NewInt(1), uint(k))
	d := api.Add(api.Sub(x, y), offset)
	bits := api.ToBinary(d, k+1)
	return api.Sub(1, bits[k])
}

// IsLessLimbs returns 1 iff a < b: the high limbs decide, the low limbs break
// the tie. The two terms are disjoint, so the sum is boolean.
//
// Each bounded comparison is sized by the wider of the two limbs, so the
// isLessBounded precondition (both operands < 2^k) holds even if the operands
// were decomposed at different widths; sizing from a alone would let a wider b
// break it.
func IsLessLimbs(api frontend.API, a, b fieldLimbs) frontend.Variable {
	hiLess := isLessBounded(api, a.hi, b.hi, max(a.hiBits, b.hiBits))
	hiEqual := api.IsZero(api.Sub(a.hi, b.hi))
	loLess := isLessBounded(api, a.lo, b.lo, max(a.loBits, b.loBits))
	return api.Add(hiLess, api.Mul(hiEqual, loLess))
}

func AssertIsLessFullField(api frontend.API, a, b frontend.Variable) {
	api.AssertIsEqual(IsLessLimbs(api, CanonicalLimbs(api, a), CanonicalLimbs(api, b)), 1)
}

func AssertStrictlyOrderedFullField(api frontend.API, lo, mid, hi frontend.Variable) {
	AssertIsLessFullField(api, lo, mid)
	AssertIsLessFullField(api, mid, hi)
}

const gapLimbBits = 128

// AssertOrderedWhen proves lo < mid < hi over canonical field integers while a boolean enabled is set,
// the gaps lo, mid-lo-1, hi-mid-1 and q-1-hi summing to q-3 without a wrap.
func AssertOrderedWhen(api frontend.API, enabled, lo, mid, hi frontend.Variable) {
	q := api.Compiler().Field()
	if q.BitLen() <= gapLimbBits+3 || q.BitLen() > 2*gapLimbBits {
		panic("ordered when: native field outside 132..256 bits")
	}
	// 1. The caller's boolean flag either keeps the operands or swaps in the satisfiable 0 < 1 < 2.
	lo = api.Mul(enabled, lo)
	mid = api.Add(api.Mul(enabled, api.Sub(mid, 1)), 1)
	hi = api.Add(api.Mul(enabled, api.Sub(hi, 2)), 2)
	w, err := api.Compiler().NewHint(orderedGapsHint, 9, lo, mid, hi)
	if err != nil {
		panic(err)
	}
	limbs, carry := w[:8], w[8]
	// 2. Bounded limbs keep both sums below 2^131, far below q, so they hold over the integers.
	rc := rangecheck.New(api)
	for _, limb := range limbs {
		rc.Check(limb, gapLimbBits)
	}
	rc.Check(carry, 2)
	// 3. The four gaps plus 2 equal q-1 exactly, so each gap and each partial sum is below q.
	base := new(big.Int).Lsh(big.NewInt(1), gapLimbBits)
	limit := new(big.Int).Sub(q, big.NewInt(1))
	limitLow := new(big.Int).And(limit, new(big.Int).Sub(base, big.NewInt(1)))
	limitHigh := new(big.Int).Rsh(limit, gapLimbBits)
	api.AssertIsEqual(api.Add(limbs[0], limbs[2], limbs[4], limbs[6], 2), api.Add(limitLow, api.Mul(base, carry)))
	api.AssertIsEqual(api.Add(limbs[1], limbs[3], limbs[5], limbs[7], carry), limitHigh)
	// 4. The gaps rebuild lo, mid and hi with a step of at least one between neighbours.
	gap := func(i int) frontend.Variable { return api.Add(limbs[2*i], api.Mul(base, limbs[2*i+1])) }
	api.AssertIsEqual(gap(0), lo)
	api.AssertIsEqual(api.Add(lo, gap(1), 1), mid)
	api.AssertIsEqual(api.Add(mid, gap(2), 1), hi)
}

func init() { solver.RegisterHint(orderedGapsHint) }

// orderedGapsHint proposes the gap limbs and the low limb carry, untrusted until
// AssertOrderedWhen range-checks and recomposes them.
func orderedGapsHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 || len(outputs) != 9 {
		return errors.New("ordered gaps: expected 3 inputs and 9 outputs")
	}
	one := big.NewInt(1)
	gaps := []*big.Int{
		new(big.Int).Set(inputs[0]),
		new(big.Int).Sub(new(big.Int).Sub(inputs[1], inputs[0]), one),
		new(big.Int).Sub(new(big.Int).Sub(inputs[2], inputs[1]), one),
		new(big.Int).Sub(new(big.Int).Sub(q, one), inputs[2]),
	}
	mask := new(big.Int).Sub(new(big.Int).Lsh(one, gapLimbBits), one)
	carry := big.NewInt(2)
	for i, gap := range gaps {
		// An unordered input leaves a negative gap, zero keeps the hint total and the circuit refuses it.
		if gap.Sign() < 0 {
			gap.SetInt64(0)
		}
		outputs[2*i].And(gap, mask)
		outputs[2*i+1].Rsh(gap, gapLimbBits)
		carry.Add(carry, outputs[2*i])
	}
	outputs[8].Rsh(carry, gapLimbBits)
	return nil
}
