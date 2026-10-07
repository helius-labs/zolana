package p256

import "github.com/consensys/gnark/frontend"

type SelfKeyAgreement struct {
	SharedX   [32]frontend.Variable
	PublicKey [33]frontend.Variable
}

func PublicKeyPacked(api frontend.API, sk [32]frontend.Variable) (lo, hi frontend.Variable) {
	c := newP256Curve(api)
	fp := newAgreementField(api)
	fr := newScalarField(api)
	scalar := fr.NewElement(agreementLimbs(api, sk[:]))
	fr.AssertIsDifferent(scalar, fr.Zero())
	public := c.ScalarMulBase(scalar)
	c.AssertIsOnCurve(public)
	x, _ := canonicalFpBytes(api, fp, &public.X)
	_, parity := canonicalFpBytes(api, fp, &public.Y)
	return packCompressedPoint(api, parity, x[:])
}

func SelfAgreeKey(api frontend.API, sk [32]frontend.Variable) SelfKeyAgreement {
	c := newP256Curve(api)
	fp := newAgreementField(api)
	fr := newScalarField(api)
	scalar := fr.NewElement(agreementLimbs(api, sk[:]))
	fr.AssertIsDifferent(scalar, fr.Zero())

	public := c.ScalarMulBase(scalar)
	c.AssertIsOnCurve(public)
	shared := c.ScalarMul(public, scalar)
	c.AssertIsOnCurve(shared)
	fp.AssertIsDifferent(&shared.Y, fp.Zero())
	fp.AssertIsDifferent(fp.Add(&shared.Y, &public.Y), fp.Zero())

	var result SelfKeyAgreement
	result.SharedX, _ = canonicalFpBytes(api, fp, &shared.X)
	publicX, _ := canonicalFpBytes(api, fp, &public.X)
	_, parity := canonicalFpBytes(api, fp, &public.Y)
	result.PublicKey[0] = api.Add(2, parity)
	copy(result.PublicKey[1:], publicX[:])
	return result
}
