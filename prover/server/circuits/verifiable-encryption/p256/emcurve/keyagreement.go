package emcurve

import (
	"github.com/consensys/gnark/frontend"
)

const uncompressedPrefix = 0x04

type KeyAgreement struct {
	RecipientLo frontend.Variable
	RecipientHi frontend.Variable
	EphemeralLo frontend.Variable
	EphemeralHi frontend.Variable
	SharedLo    frontend.Variable
	SharedHi    frontend.Variable
}

func AgreeKey(api frontend.API, ephemeralSk [32]frontend.Variable, recipientPk [65]frontend.Variable) KeyAgreement {
	return AgreeKeyFor(api, ephemeralSk, recipientPk, true)
}

func AgreeKeyFor(api frontend.API, ephemeralSk [32]frontend.Variable, recipientPk [65]frontend.Variable, lookups bool) KeyAgreement {
	c := newCurveFor(api, lookups)
	limbBits := c.lay.LimbBits
	api.AssertIsEqual(recipientPk[0], uncompressedPrefix)
	rc := c.rangeChecker()
	for _, b := range recipientPk[1:] {
		rc.Check(b, 8)
	}
	recipient := &point{X: c.fp.Reduced(c.fieldLimbs(recipientPk[1:33])), Y: c.fp.Reduced(c.fieldLimbs(recipientPk[33:65]))}
	c.fp.AssertCanonical(recipient.X)
	c.fp.AssertCanonical(recipient.Y)
	c.assertOnCurve(recipient)
	_, recipientParity := c.splitLowBits(recipientPk[64], 1, 8)

	var result KeyAgreement
	result.RecipientLo = api.Add(api.Mul(api.Add(2, recipientParity), pow2(240)), bigEndianSum(api, recipientPk[1:31]))
	result.RecipientHi = bigEndianSum(api, recipientPk[31:33])

	scalar := c.fr.FromLimbs(c.fieldLimbs(ephemeralSk[:]))
	shared := c.scalarMulChecked(recipient, scalar)

	ephemeral := c.scalarMulBase(scalar)
	result.EphemeralLo, result.EphemeralHi = c.compressedPacking(c.canonicalLimbs(ephemeral.X), c.canonicalLimbs(ephemeral.Y), limbBits)

	sharedX := c.canonicalLimbs(shared.X)
	high, low := c.splitLowBits(sharedX[0], 8, limbBits)
	result.SharedLo = packAbove(api, high, sharedX, 8, limbBits)
	result.SharedHi = low
	return result
}

func (c *curve) fieldLimbs(bytes []frontend.Variable) []frontend.Variable {
	api := c.api
	perLimb := c.lay.LimbBits / 8
	var limbs []frontend.Variable
	for end := len(bytes); end > 0; end -= perLimb {
		limbs = append(limbs, bigEndianSum(api, bytes[max(0, end-perLimb):end]))
	}
	return limbs
}

func bigEndianSum(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	sum := frontend.Variable(0)
	for _, b := range bytes {
		sum = api.Add(api.Mul(sum, 256), b)
	}
	return sum
}

func packAbove(api frontend.API, lowLimbHigh frontend.Variable, limbs []frontend.Variable, lowBits, limbBits int) frontend.Variable {
	sum := lowLimbHigh
	for i := 1; i < len(limbs); i++ {
		sum = api.Add(sum, api.Mul(limbs[i], pow2(limbBits*i-lowBits)))
	}
	return sum
}

func (c *curve) compressedPacking(xLimbs, yLimbs []frontend.Variable, limbBits int) (lo, hi frontend.Variable) {
	api := c.api
	_, parity := c.splitLowBits(yLimbs[0], 1, limbBits)
	high, low := c.splitLowBits(xLimbs[0], 16, limbBits)
	lo = api.Add(api.Mul(api.Add(2, parity), pow2(240)), packAbove(api, high, xLimbs, 16, limbBits))
	return lo, low
}
