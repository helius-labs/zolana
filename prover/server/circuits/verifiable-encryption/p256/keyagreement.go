package p256

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"

	"zolana/prover/circuits/gadget"
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

	api.AssertIsEqual(recipientPk[0], uncompressedPrefix)
	rc := rangecheck.New(api)
	for _, b := range recipientPk[1:] {
		rc.Check(b, 8)
	}

	recipient := &agreementPoint{
		X: *fp.NewElement(agreementLimbs(api, recipientPk[1:33])),
		Y: *fp.NewElement(agreementLimbs(api, recipientPk[33:65])),
	}
	fp.AssertIsInRange(&recipient.X)
	fp.AssertIsInRange(&recipient.Y)
	c.AssertIsOnCurve(recipient)

	// gnark >= v0.16.4 (GHSA-7fx8-hmgc-82jp) constrains the hinted ScalarMul
	// output to the curve, and P-256 has prime order, so with an on-curve
	// recipient and a nonzero scalar both products are the honest finite points.
	ephemeral := DerivePublicKey(api, ephemeralSk)
	shared := c.ScalarMul(recipient, ephemeral.scalar)

	sharedX, _ := canonicalFpBytes(api, fp, &shared.X)
	recipientParity := api.ToBinary(recipientPk[64], 8)[0]

	var result KeyAgreement
	result.RecipientLo, result.RecipientHi = packCompressedPoint(api, recipientParity, recipientPk[1:33])
	result.EphemeralLo, result.EphemeralHi = ephemeral.Packed(api)
	result.SharedLo, result.SharedHi = packSharedX(api, sharedX[:])
	return result
}

func agreementLimbs(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	limbs := make([]frontend.Variable, 4)
	for i := range limbs {
		end := len(bytes) - 8*i
		limbs[i] = gadget.BytesToField(api, bytes[end-8:end])
	}
	return limbs
}

func limbBytesAndLsb(api frontend.API, limb frontend.Variable) ([8]frontend.Variable, frontend.Variable) {
	bits := api.ToBinary(limb, 64)
	var bytes [8]frontend.Variable
	copy(bytes[:], gadget.BitsToBytesBE(api, bits))
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

func packCompressedPoint(api frontend.API, parity frontend.Variable, x []frontend.Variable) (lo, hi frontend.Variable) {
	prefix := api.Mul(api.Add(2, parity), new(big.Int).Lsh(big.NewInt(1), 240))
	return api.Add(prefix, gadget.BytesToField(api, x[0:30])), gadget.BytesToField(api, x[30:32])
}

func packSharedX(api frontend.API, x []frontend.Variable) (lo, hi frontend.Variable) {
	return gadget.BytesToField(api, x[0:31]), x[31]
}
