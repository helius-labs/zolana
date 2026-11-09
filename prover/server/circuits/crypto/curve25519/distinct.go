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
func PackHalves(api frontend.API, e *nonnative.Element) (lo, hi frontend.Variable) {
	lay := e.Layout()
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
	// Each packed difference stays below 2^(cut*LimbBits+1) and must not wrap.
	if cut*lay.LimbBits+1 >= api.Compiler().FieldBitLen() {
		panic("curve25519: packed halves can wrap the native field")
	}
	mask := new(big.Int).Sub(Pow2(cut*lay.LimbBits), big.NewInt(1))
	p := f.Modulus()
	pl := new(big.Int).And(p, mask)
	ph := new(big.Int).Rsh(p, uint(cut*lay.LimbBits))
	al, ah := PackHalves(api, a)
	bl, bh := PackHalves(api, b)
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

// AssertSlopeGuard proves mu*(mu+2*lambda) != 0 mod the prime p, so neither factor is zero mod p.
func AssertSlopeGuard(api frontend.API, f *nonnative.Field, lambda, mu *nonnative.Element) {
	sum := f.Lin([]int64{1, 2}, mu, lambda)
	product := f.EvalProjected(nonnative.T(1, mu, sum))
	AssertDistinct(api, f, product, f.Const(new(big.Int)))
}
