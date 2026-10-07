package p256

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

type KeyAgreement struct {
	RecipientLo frontend.Variable
	RecipientHi frontend.Variable
	EphemeralLo frontend.Variable
	EphemeralHi frontend.Variable
	SharedLo    frontend.Variable
	SharedHi    frontend.Variable
}

type (
	agreementField   = emulated.Field[emulated.P256Fp]
	agreementElement = emulated.Element[emulated.P256Fp]
	agreementPoint   = sw_emulated.AffinePoint[emulated.P256Fp]
)

const uncompressedPrefix = 0x04

func AgreeKey(api frontend.API, ephemeralSk [32]frontend.Variable, recipientPk [65]frontend.Variable) KeyAgreement {
	c := newP256Curve(api)
	fp := newAgreementField(api)
	fr := newScalarField(api)

	api.AssertIsEqual(recipientPk[0], uncompressedPrefix)
	rc := rangecheck.New(api)
	for _, b := range recipientPk[1:] {
		rc.Check(b, 8)
	}

	recipient := &agreementPoint{
		X: *fp.NewElement(agreementLimbs(api, recipientPk[1:33])),
		Y: *fp.NewElement(agreementLimbs(api, recipientPk[33:65])),
	}
	scalar := fr.NewElement(agreementLimbs(api, ephemeralSk[:]))

	fp.AssertIsInRange(&recipient.X)
	fp.AssertIsInRange(&recipient.Y)
	c.AssertIsOnCurve(recipient)
	fr.AssertIsDifferent(scalar, fr.Zero())

	// gnark >= v0.16.4 (GHSA-7fx8-hmgc-82jp) constrains the hinted ScalarMul
	// output to the curve, and P-256 has prime order, so with an on-curve
	// recipient and a nonzero scalar both products are the honest finite points.
	shared := c.ScalarMul(recipient, scalar)
	ephemeral := c.ScalarMulBase(scalar)

	sharedX, _ := canonicalFpBytes(api, fp, &shared.X)
	ephemeralX, _ := canonicalFpBytes(api, fp, &ephemeral.X)
	_, ephemeralParity := canonicalFpBytes(api, fp, &ephemeral.Y)
	recipientParity := api.ToBinary(recipientPk[64], 8)[0]

	var result KeyAgreement
	result.RecipientLo, result.RecipientHi = packCompressedPoint(api, recipientParity, recipientPk[1:33])
	result.EphemeralLo, result.EphemeralHi = packCompressedPoint(api, ephemeralParity, ephemeralX[:])
	result.SharedLo, result.SharedHi = packSharedX(api, sharedX[:])
	return result
}

func agreementLimbs(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	limbs := make([]frontend.Variable, 4)
	for i := range limbs {
		end := len(bytes) - 8*i
		limbs[i] = bigEndianSum(api, bytes[end-8:end])
	}
	return limbs
}

func limbBytesAndLsb(api frontend.API, limb frontend.Variable) ([8]frontend.Variable, frontend.Variable) {
	bits := api.ToBinary(limb, 64)
	var bytes [8]frontend.Variable
	for i := range bytes {
		start := (7 - i) * 8
		bytes[i] = api.FromBinary(bits[start : start+8]...)
	}
	return bytes, bits[0]
}

func canonicalFpBytes(api frontend.API, fp *agreementField, e *agreementElement) ([32]frontend.Variable, frontend.Variable) {
	reduced := fp.ReduceStrict(e)
	var bytes [32]frontend.Variable
	var lsb frontend.Variable
	for i, limb := range reduced.Limbs {
		limbBE, low := limbBytesAndLsb(api, limb)
		if i == 0 {
			lsb = low
		}
		copy(bytes[(3-i)*8:], limbBE[:])
	}
	return bytes, lsb
}

func bigEndianSum(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	sum := frontend.Variable(0)
	for _, b := range bytes {
		sum = api.Add(api.Mul(sum, 256), b)
	}
	return sum
}

func packCompressedPoint(api frontend.API, parity frontend.Variable, x []frontend.Variable) (lo, hi frontend.Variable) {
	prefix := api.Mul(api.Add(2, parity), new(big.Int).Lsh(big.NewInt(1), 240))
	return api.Add(prefix, bigEndianSum(api, x[0:30])), bigEndianSum(api, x[30:32])
}

func packSharedX(api frontend.API, x []frontend.Variable) (lo, hi frontend.Variable) {
	return bigEndianSum(api, x[0:31]), x[31]
}
