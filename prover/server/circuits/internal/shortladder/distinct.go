package shortladder

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/r1c"
)

// PackHalves recomposes the limbs below and from the middle limb index into
// two native values. With reduced or balanced limbs each half stays far below
// the native modulus, so equations on the halves lift to the integers.
func PackHalves(api frontend.API, lay emfield.Layout, e *emfield.Element) (lo, hi frontend.Variable) {
	pack := func(start, end int) frontend.Variable {
		v := frontend.Variable(0)
		for i := start; i < end; i++ {
			v = api.Add(v, api.Mul(e.Limbs()[i], Pow2((i-start)*lay.LimbBits)))
		}
		return v
	}
	cut := (lay.NbLimbs + 1) / 2
	return pack(0, cut), pack(cut, lay.NbLimbs)
}

// AssertDistinct rejects equality modulo p between two reduced coordinates.
// Reduced widths must already be constrained. Values below 2^255 that are
// equal modulo p differ by 0 or +/-p, and a low-half borrow would need a high
// difference of +/-2^(255-cut), so three packed pairs cover every alias. The
// nonzero hint keeps the caller's registered name so stored constraint
// systems keep resolving it; PackedNonzero is its body.
func AssertDistinct(api frontend.API, f *emfield.Field, a, b *emfield.Element, nonzero solver.Hint) {
	widths := f.ReducedWidths()
	if !a.IsReduced(widths) || !b.IsReduced(widths) {
		panic("shortladder: distinct coordinate guard needs reduced coordinates")
	}
	lay := f.Layout()
	cut := (lay.NbLimbs + 1) / 2
	mask := new(big.Int).Sub(Pow2(cut*lay.LimbBits), big.NewInt(1))
	p := f.Modulus()
	pl := new(big.Int).And(p, mask)
	ph := new(big.Int).Rsh(p, uint(cut*lay.LimbBits))
	al, ah := PackHalves(api, lay, a)
	bl, bh := PackHalves(api, lay, b)
	lo, hi := api.Sub(al, bl), api.Sub(ah, bh)
	for _, k := range []int64{-1, 0, 1} {
		dl := api.Sub(lo, new(big.Int).Mul(big.NewInt(k), pl))
		dh := api.Sub(hi, new(big.Int).Mul(big.NewInt(k), ph))
		inv, err := api.Compiler().NewHint(nonzero, 2, dl, dh)
		if err != nil {
			panic(err)
		}
		r1c.AssertProduct(api, inv[1], dh, api.Sub(1, api.Mul(inv[0], dl)))
	}
}

// PackedNonzero proposes inverses certifying that two native values are not
// both zero. The consuming product equation checks the certificate, so the
// host zero handling is not itself a nonzero assertion.
func PackedNonzero(q *big.Int, in, out []*big.Int) error {
	if len(in) != 2 || len(out) != 2 {
		return errors.New("shortladder: packed nonzero hint shape")
	}
	out[0].SetInt64(0)
	out[1].SetInt64(0)
	if in[0].Sign() != 0 {
		out[0].ModInverse(in[0], q)
	} else if in[1].Sign() != 0 {
		out[1].ModInverse(in[1], q)
	}
	return nil
}
