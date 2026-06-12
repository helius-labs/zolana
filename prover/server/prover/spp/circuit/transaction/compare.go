package transaction

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// The nullifier tree accepts any canonical field element (init sentinel p-1,
// insertable domain 0 < v < p-1), so ordering proofs compare full field
// values. A single 2^N-offset decomposition — sound for narrow domains where
// a + 2^N - b cannot wrap mod p — is unsound here: for a near p the offset sum
// wraps and a false "a < b" decomposes cleanly, forging non-inclusion. Instead
// each operand is decomposed canonically once and compared as two bounded
// limbs.

// fieldLimbs is a field element split at the bit midpoint into two bounded
// limbs. Built only by canonicalLimbs, which pins the decomposition.
type fieldLimbs struct {
	lo, hi         frontend.Variable
	loBits, hiBits int
}

// canonicalLimbs decomposes x with the full-width ToBinary and returns the two
// halves. The full width is load-bearing: it constrains the bits to x's
// canonical (< p) value, so x and x+p cannot present different limbs. Don't
// pass a smaller NbDigits; it drops the < p check. Pinned by
// TestFullFieldCompareRejectsAliasBits.
func canonicalLimbs(api frontend.API, x frontend.Variable) fieldLimbs {
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

// isLessLimbs returns 1 iff a < b: the high limbs decide, the low limbs break
// the tie. The two terms are disjoint, so the sum is boolean.
func isLessLimbs(api frontend.API, a, b fieldLimbs) frontend.Variable {
	hiLess := isLessBounded(api, a.hi, b.hi, a.hiBits)
	hiEqual := api.IsZero(api.Sub(a.hi, b.hi))
	loLess := isLessBounded(api, a.lo, b.lo, a.loBits)
	return api.Add(hiLess, api.Mul(hiEqual, loLess))
}
