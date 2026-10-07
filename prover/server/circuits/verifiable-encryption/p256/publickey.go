package p256

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

// PublicKey is a secret scalar together with the point ScalarMulBase derived
// from it in this circuit. The fields stay unexported so a caller cannot pair
// a secret with a point the circuit did not derive from it.
type PublicKey struct {
	scalar *emulated.Element[emulated.P256Fr]
	point  *agreementPoint
	x      [32]frontend.Variable
	parity frontend.Variable
}

type SelfKeyAgreement struct {
	SharedX   [32]frontend.Variable
	PublicKey [33]frontend.Variable
}

// DerivePublicKey range-checks the big-endian secret key bytes, reduces the
// scalar modulo the group order, refuses zero and derives the public point.
func DerivePublicKey(api frontend.API, sk [32]frontend.Variable) PublicKey {
	fp := newAgreementField(api)
	fr := newScalarField(api)

	rc := rangecheck.New(api)
	for _, b := range sk {
		rc.Check(b, 8)
	}
	scalar := fr.NewElement(agreementLimbs(api, sk[:]))
	fr.AssertIsDifferent(scalar, fr.Zero())

	point := newP256Curve(api).ScalarMulBase(scalar)
	x, _ := canonicalFpBytes(api, fp, &point.X)
	_, parity := canonicalFpBytes(api, fp, &point.Y)
	return PublicKey{scalar: scalar, point: point, x: x, parity: parity}
}

func (k PublicKey) Packed(api frontend.API) (lo, hi frontend.Variable) {
	return packCompressedPoint(api, k.parity, k.x[:])
}

func (k PublicKey) Compressed(api frontend.API) [33]frontend.Variable {
	var compressed [33]frontend.Variable
	compressed[0] = api.Add(2, k.parity)
	copy(compressed[1:], k.x[:])
	return compressed
}

// SelfAgreeKey agrees a key between a public key and its own secret, reusing
// the point DerivePublicKey constrained instead of deriving it again.
func SelfAgreeKey(api frontend.API, key PublicKey) SelfKeyAgreement {
	shared := newP256Curve(api).ScalarMul(key.point, key.scalar)
	var result SelfKeyAgreement
	result.SharedX, _ = canonicalFpBytes(api, newAgreementField(api), &shared.X)
	result.PublicKey = key.Compressed(api)
	return result
}
