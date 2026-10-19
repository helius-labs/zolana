package curve25519

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

// PackHalves recomposes the limbs below and from the middle limb index into
// two native values. With reduced or balanced limbs each half stays far below
// the native modulus, so equations on the halves lift to the integers.
func PackHalves(api frontend.API, lay nonnative.Layout, e *nonnative.Element) (lo, hi frontend.Variable) {
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
// difference of +/-2^(255-cut), so three packed pairs cover every alias.
func AssertDistinct(api frontend.API, f *nonnative.Field, a, b *nonnative.Element) {
	widths := f.ReducedWidths()
	if !a.IsReduced(widths) || !b.IsReduced(widths) {
		panic("curve25519: distinct coordinate guard needs reduced coordinates")
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
		inv, err := api.Compiler().NewHint(PackedNonzero, 2, dl, dh)
		if err != nil {
			panic(err)
		}
		assertProduct(api, inv[1], dh, api.Sub(1, api.Mul(inv[0], dl)))
	}
}

func init() { solver.RegisterHint(PackedNonzero) }

// PackedNonzero proposes inverses certifying that two native values are not
// both zero. The consuming product equation checks the certificate, so the
// host zero handling is not itself a nonzero assertion.
func PackedNonzero(q *big.Int, in, out []*big.Int) error {
	if len(in) != 2 || len(out) != 2 {
		return errors.New("curve25519: packed nonzero hint shape")
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

// AssertSlopeGuard proves mu*(mu+2*lambda) != 0 mod p for balanced slopes.
func AssertSlopeGuard(api frontend.API, f *nonnative.Field, lambda, mu *nonnative.Element) {
	p := f.Modulus()
	bitsPerLimb := f.Layout().LimbBits
	offset := new(big.Int)
	for i, w := range f.ReducedWidths() {
		offset.Add(offset, new(big.Int).Lsh(Pow2(w-1), uint(i*bitsPerLimb)))
	}
	maximum := new(big.Int).Sub(new(big.Int).Sub(Pow2(p.BitLen()), big.NewInt(1)), offset)
	if offset.Cmp(maximum) > 0 {
		maximum.Set(offset)
	}
	if maximum.Cmp(p) >= 0 || new(big.Int).Mul(maximum, big.NewInt(3)).Cmp(new(big.Int).Lsh(p, 1)) >= 0 {
		panic("curve25519: slope guard needs |mu|<p and |mu+2*lambda|<2p")
	}
	native := func(e *nonnative.Element) frontend.Variable {
		sum := frontend.Variable(0)
		for i, l := range e.Limbs() {
			sum = api.Add(sum, api.Mul(l, Pow2(i*bitsPerLimb)))
		}
		return sum
	}
	m := native(mu)
	s := api.Add(m, api.Mul(native(lambda), 2))
	// Zero mod p is the integer 0 or +/-p here, a native collision only rejects.
	api.AssertIsDifferent(api.Mul(m, s, api.Sub(api.Mul(s, s), new(big.Int).Mul(p, p))), 0)
}
