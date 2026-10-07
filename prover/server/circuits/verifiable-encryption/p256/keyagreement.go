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
	recipient, recipientParity := canonicalRecipient(api, c, fp, recipientPk[1:])

	// gnark >= v0.16.4 (GHSA-7fx8-hmgc-82jp) constrains the hinted ScalarMul
	// output to the curve, and P-256 has prime order, so with a finite on-curve
	// recipient and a nonzero scalar both products are the honest finite points.
	ephemeral := DerivePublicKey(api, ephemeralSk)
	shared := c.ScalarMul(recipient, ephemeral.scalar)

	sharedX, _ := canonicalFpBytes(api, fp, &shared.X)

	var result KeyAgreement
	result.RecipientLo, result.RecipientHi = packCompressedPoint(api, recipientParity, recipientPk[1:33])
	result.EphemeralLo, result.EphemeralHi = ephemeral.Packed(api)
	result.SharedLo, result.SharedHi = packSharedX(api, sharedX[:])
	return result
}

// canonicalRecipient decodes a finite, on-curve point from x || y bytes and
// returns it with the parity of y. The parity is read from the last y byte,
// which is the canonical parity only because the same function has already
// forced y < p, so the two cannot be separated by a refactor.
func canonicalRecipient(
	api frontend.API,
	c *sw_emulated.Curve[emulated.P256Fp, emulated.P256Fr],
	fp *agreementField,
	bytes []frontend.Variable,
) (*agreementPoint, frontend.Variable) {
	rc := rangecheck.New(api)
	for _, b := range bytes {
		rc.Check(b, 8)
	}

	recipient := &agreementPoint{
		X: *fp.NewElement(agreementLimbs(api, bytes[0:32])),
		Y: *fp.NewElement(agreementLimbs(api, bytes[32:64])),
	}
	fp.AssertIsInRange(&recipient.X)
	fp.AssertIsInRange(&recipient.Y)
	c.AssertIsOnCurve(recipient)
	// AssertIsOnCurve admits (0,0) as its infinity encoding. A recipient at
	// infinity makes the shared point infinity too, so the shared secret would
	// depend only on public values and anyone could decrypt the envelope.
	api.AssertIsEqual(api.And(fp.IsZero(&recipient.X), fp.IsZero(&recipient.Y)), 0)

	return recipient, api.ToBinary(bytes[63], 8)[0]
}

func agreementLimbs(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	limbs := make([]frontend.Variable, 4)
	for i := range limbs {
		end := len(bytes) - 8*i
		limbs[i] = gadget.BytesToField(api, bytes[end-8:end])
	}
	return limbs
}

func canonicalFpBytes(api frontend.API, fp *agreementField, e *agreementElement) ([32]frontend.Variable, frontend.Variable) {
	bits := fp.ToBitsCanonical(e)
	var bytes [32]frontend.Variable
	copy(bytes[:], gadget.BitsToBytesBE(api, bits))
	return bytes, bits[0]
}

func packCompressedPoint(api frontend.API, parity frontend.Variable, x []frontend.Variable) (lo, hi frontend.Variable) {
	prefix := api.Mul(api.Add(2, parity), new(big.Int).Lsh(big.NewInt(1), 240))
	return api.Add(prefix, gadget.BytesToField(api, x[0:30])), gadget.BytesToField(api, x[30:32])
}

func packSharedX(api frontend.API, x []frontend.Variable) (lo, hi frontend.Variable) {
	return gadget.BytesToField(api, x[0:31]), x[31]
}
