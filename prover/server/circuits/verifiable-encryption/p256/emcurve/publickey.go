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
	rangeChecker := newCurve(api).rangeChecker()
	for _, byteValue := range bytes {
		rangeChecker.Check(byteValue, 8)
	}
}

// DerivePublicKey range-checks the big-endian secret key bytes, refuses a
// scalar that is zero modulo the group order and derives the public point.
func DerivePublicKey(api frontend.API, secretKeyBytes [32]frontend.Variable) PublicKey {
	c := newCurve(api)
	// 1. Constrain the input bytes and reject a scalar with zero residue.
	AssertBytes(api, secretKeyBytes[:])
	scalar := c.fr.FromLimbs(c.fieldLimbs(secretKeyBytes[:]))
	c.assertNonZeroResidue(scalar)
	// 2. Derive the public point and retain its canonical coordinates for reuse.
	publicPoint := c.scalarMulBase(scalar)
	key := PublicKey{scalar: scalar, xLimbs: c.canonicalLimbs(publicPoint.X), yLimbs: c.canonicalLimbs(publicPoint.Y)}
	copy(key.x[:], c.toBytes(publicPoint.X))
	return key
}

func (k PublicKey) Packed(api frontend.API) (lo, hi frontend.Variable) {
	c := newCurve(api)
	return c.compressedPacking(k.xLimbs, k.yLimbs, c.layout.LimbBits)
}

func (k PublicKey) Compressed(api frontend.API) [33]frontend.Variable {
	c := newCurve(api)
	_, parity := c.splitLowBits(k.yLimbs[0], 1, c.layout.LimbBits)
	var compressed [33]frontend.Variable
	compressed[0] = api.Add(2, parity)
	copy(compressed[1:], k.x[:])
	return compressed
}

// SelfAgreeKey agrees a key between a public key and its own secret s. The
// shared point [s]([s]G) is [s^2 mod n]G, so it uses the fixed-base comb.
func SelfAgreeKey(api frontend.API, key PublicKey) SelfKeyAgreement {
	c := newCurve(api)
	// 1. Compute the self-agreement point [s²]G using the fixed-base table.
	squaredScalar := c.fr.Eval(T(1, key.scalar, key.scalar))
	shared := c.scalarMulBase(squaredScalar)
	// 2. Return canonical shared-x bytes and the compressed public key.
	var agreement SelfKeyAgreement
	copy(agreement.SharedX[:], c.toBytes(shared.X))
	agreement.PublicKey = key.Compressed(api)
	return agreement
}

func (c *curve) assertNonZeroResidue(s *frElement) {
	reduced := c.fr.Eval(T(1, s))
	c.fr.AssertCanonical(reduced)
	c.api.AssertIsDifferent(c.api.Add(0, 0, reduced.Limbs()...), 0)
}
