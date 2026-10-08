package emcurve

import (
	"github.com/consensys/gnark/frontend"
)

// PublicKey is a secret scalar together with the point coordinates
// scalarMulBase derived from it in this circuit. The fields stay unexported so
// a caller cannot pair a secret with a point the circuit did not derive from it.
type PublicKey struct {
	scalar *frElement
	xLimbs []frontend.Variable
	yLimbs []frontend.Variable
	x      [32]frontend.Variable
}

type SelfKeyAgreement struct {
	SharedX   [32]frontend.Variable
	PublicKey [33]frontend.Variable
}

// AssertBytes range-checks every value to 8 bits on the shared lookup table.
func AssertBytes(api frontend.API, bytes []frontend.Variable) {
	rc := newCurve(api).rangeChecker()
	for _, b := range bytes {
		rc.Check(b, 8)
	}
}

// DerivePublicKey range-checks the big-endian secret key bytes, refuses a
// scalar that is zero modulo the group order and derives the public point.
func DerivePublicKey(api frontend.API, sk [32]frontend.Variable) PublicKey {
	c := newCurve(api)
	AssertBytes(api, sk[:])
	scalar := c.fr.FromLimbs(c.fieldLimbs(sk[:]))
	c.assertNonZeroResidue(scalar)
	p := c.scalarMulBase(scalar)
	key := PublicKey{scalar: scalar, xLimbs: c.canonicalLimbs(p.X), yLimbs: c.canonicalLimbs(p.Y)}
	copy(key.x[:], c.toBytes(p.X))
	return key
}

func (k PublicKey) Packed(api frontend.API) (lo, hi frontend.Variable) {
	c := newCurve(api)
	return c.compressedPacking(k.xLimbs, k.yLimbs, c.lay.LimbBits)
}

func (k PublicKey) Compressed(api frontend.API) [33]frontend.Variable {
	c := newCurve(api)
	_, parity := c.splitLowBits(k.yLimbs[0], 1, c.lay.LimbBits)
	var compressed [33]frontend.Variable
	compressed[0] = api.Add(2, parity)
	copy(compressed[1:], k.x[:])
	return compressed
}

// SelfAgreeKey agrees a key between a public key and its own secret s. The
// shared point [s]([s]G) is [s^2 mod n]G, so it runs on the fixed-base comb,
// which is complete for every non-zero scalar, instead of the variable-base
// ladder, whose distinct-x guards refuse s = +-1 and s = +-3.
func SelfAgreeKey(api frontend.API, key PublicKey) SelfKeyAgreement {
	c := newCurve(api)
	shared := c.scalarMulBase(c.fr.Eval(T(1, key.scalar, key.scalar)))
	var result SelfKeyAgreement
	copy(result.SharedX[:], c.toBytes(shared.X))
	result.PublicKey = key.Compressed(api)
	return result
}

func (c *curve) assertNonZeroResidue(s *frElement) {
	reduced := c.fr.Eval(T(1, s))
	c.fr.AssertCanonical(reduced)
	c.api.AssertIsDifferent(c.api.Add(0, 0, reduced.Limbs()...), 0)
}
