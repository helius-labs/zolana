package shortchecker

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/r1c"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/shortladder"
)

// assertLadderOutputDistinct proves mu != 0 and mu+2*lambda != 0 modulo p.
// Both slopes must have HintBalanced's signed digit bounds. Unlike a single
// native-field nonzero test, the packed certificates accept nonzero integers
// that happen to equal a multiple of the native modulus.
func (c *curve) assertLadderOutputDistinct(lambda, mu *fpElement) {
	// 1. Verify the compile-time intervals used to lift packed equations.
	c.checkExactSlopeGuardBounds()
	api := c.api
	cut := (c.lay.NbLimbs + 1) / 2
	// 2. Certify mu!=0 with two small signed chunks, avoiding native aliases.
	ml, mh := shortladder.PackHalves(api, c.lay, mu)
	w, err := api.Compiler().NewHint(shortPackedNonzeroHint, 2, ml, mh)
	if err != nil {
		panic(err)
	}
	// Each packed signed half has magnitude below q. Balanced digits have
	// a unique integer representation of zero, so these two tests are exact.
	r1c.AssertProduct(api, w[1], mh, api.Sub(1, api.Mul(w[0], ml)))

	// 3. Detect when S=mu+2*lambda aliases 0 or +/-p in the native field.
	ll, lh := shortladder.PackHalves(api, c.lay, lambda)
	lo := api.Add(ml, api.Mul(2, ll))
	hi := api.Add(mh, api.Mul(2, lh))
	cutBits := cut * c.lay.LimbBits
	B := pow2(cutBits)
	p, q := c.fp.Modulus(), api.Compiler().Field()
	sum := api.Add(lo, api.Mul(hi, B))
	z := api.IsZero(api.Mul(sum, api.Sub(sum, p), api.Add(sum, p)))
	in := []frontend.Variable{c.lay.LimbBits, c.lay.NbLimbs}
	in = append(in, mu.Limbs()...)
	in = append(in, lambda.Limbs()...)
	out, err := api.Compiler().NewHint(shortSlopeAliasHint, 3, in...)
	if err != nil {
		panic(err)
	}
	// 4. On those roots, require a bounded nonzero native-modulus multiple.
	// Packed carries lift the certificate to integers and reject actual p multiples.
	k, n, inv := out[0], out[1], out[2]
	c.fp.RangeChecker().Check(api.Add(n, 8), 4)
	r1c.AssertProduct(api, n, inv, z)
	mask := new(big.Int).Sub(B, big.NewInt(1))
	pl, ql := new(big.Int).And(p, mask), new(big.Int).And(q, mask)
	ph, qh := new(big.Int).Rsh(p, uint(cutBits)), new(big.Int).Rsh(q, uint(cutBits))
	low := api.Sub(lo, api.Mul(k, pl), api.Mul(n, ql))
	carry := api.Mul(api.Mul(z, low), new(big.Int).ModInverse(B, q))
	c.fp.RangeChecker().Check(api.Add(carry, 16), 5)
	r1c.AssertProduct(api, z, api.Add(api.Sub(hi, api.Mul(k, ph), api.Mul(n, qh)), carry), 0)
	// If z=1, combining low/high equations gives sum=k*p modulo q.
	// The root test therefore fixes k to -1,0,1 in Fq, even without a
	// separate range check. The packed equations then lift to integers as
	// sum=k*p+n*q. Requiring n!=0 rejects exactly the actual p-multiples.
}

// checkExactSlopeGuardBounds validates the integer bounds used by the slope
// certificate at compile time. It rejects fields or layouts where packed
// equations could wrap or a zero modulo p could escape the enumerated aliases.
func (c *curve) checkExactSlopeGuardBounds() {
	// 1. Require the Curve25519 modulus and derive the balanced-digit interval.
	p, q := c.fp.Modulus(), c.api.Compiler().Field()
	if p.Cmp(prime()) != 0 {
		panic("x25519: exact slope guard requires the Curve25519 field")
	}
	widths := c.fp.ReducedWidths()
	offset := new(big.Int)
	for i, w := range widths {
		offset.Add(offset, new(big.Int).Lsh(pow2(w-1), uint(i*c.lay.LimbBits)))
	}
	maximum := new(big.Int).Sub(new(big.Int).Sub(pow2(255), big.NewInt(1)), offset)
	if offset.Cmp(maximum) > 0 {
		maximum.Set(offset)
	}
	// 2. Check alias coverage and that both packed carry equations lift to integers.
	cut := ((c.lay.NbLimbs + 1) / 2) * c.lay.LimbBits
	if maximum.Cmp(p) >= 0 || new(big.Int).Mul(maximum, big.NewInt(3)).Cmp(new(big.Int).Lsh(p, 1)) >= 0 || new(big.Int).Mul(p, big.NewInt(3)).Cmp(new(big.Int).Lsh(q, 3)) >= 0 || new(big.Int).Mul(big.NewInt(32), pow2(cut)).Cmp(q) >= 0 || new(big.Int).Mul(big.NewInt(32), pow2(255-cut)).Cmp(q) >= 0 {
		panic("x25519: exact slope guard bounds do not fit the native field")
	}
}

// init registers nonzero-certificate witnesses. Consumers constrain their
// products and bounded carries, so solver output is never accepted on trust.
func init() { solver.RegisterHint(shortPackedNonzeroHint, shortSlopeAliasHint) }

// shortPackedNonzeroHint proposes inverses certifying that two native values
// are not both zero. The consuming product equation checks this certificate.
// The name stays registered here so stored constraint systems resolve it.
func shortPackedNonzeroHint(q *big.Int, in, out []*big.Int) error {
	return shortladder.PackedNonzero(q, in, out)
}

// shortSlopeAliasHint proposes k,n,1/n for S=k*p+n*q when S aliases 0 or +/-p
// in the native field. assertLadderOutputDistinct constrains the root, signed
// carry bounds and n!=0. This variable-time witness computation is untrusted.
func shortSlopeAliasHint(q *big.Int, in, out []*big.Int) error {
	// 1. Validate the public limb shape.
	if len(in) < 2 || len(out) != 3 || !in[0].IsUint64() || !in[1].IsUint64() || in[0].Uint64() == 0 || in[0].Uint64() > 255 || in[1].Uint64() == 0 || in[1].Uint64() > 255 || len(in) != 2+2*int(in[1].Uint64()) {
		return errors.New("x25519: slope alias hint shape")
	}
	// 2. Reconstruct the signed integer S from balanced native residues.
	bits, n := int(in[0].Int64()), int(in[1].Int64())
	s := shortladder.BalancedInteger(q, in[2:2+n], bits)
	s.Add(s, new(big.Int).Lsh(shortladder.BalancedInteger(q, in[2+n:], bits), 1))
	r := new(big.Int).Mod(s, q)
	p := prime()
	for _, v := range out {
		v.SetInt64(0)
	}
	// 3. Propose the matching alias and native-modulus quotient certificate.
	for _, k := range []int64{-1, 0, 1} {
		kp := new(big.Int).Mul(big.NewInt(k), p)
		if r.Cmp(new(big.Int).Mod(kp, q)) != 0 {
			continue
		}
		nativeMultiple := new(big.Int).Sub(s, kp)
		nativeMultiple.Quo(nativeMultiple, q)
		out[0].SetInt64(k)
		out[1].Set(nativeMultiple)
		if nativeMultiple.Sign() != 0 {
			out[2].ModInverse(nativeMultiple, q)
		}
		break
	}
	return nil
}
