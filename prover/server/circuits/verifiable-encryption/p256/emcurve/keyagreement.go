package emcurve

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
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

// AgreeKey computes packed key-agreement outputs using lookup range checks.
// Both the ephemeral scalar bytes and recipient encoding are constrained here.
func AgreeKey(api frontend.API, ephemeralSecretKey [32]frontend.Variable, recipientPubkey [65]frontend.Variable) KeyAgreement {
	c := newCurve(api)
	limbBits := c.layout.LimbBits
	// 1. Validate the recipient encoding and constrain its canonical curve point.
	recipient := c.parseKey(recipientPubkey)
	c.assertOnCurveAt(recipient)
	_, recipientParity := c.splitLowBits(recipientPubkey[64], 1, 8)

	// 2. Pack the recipient with its compressed-point prefix.
	var agreement KeyAgreement
	compressedPrefix := api.Add(2, recipientParity)
	weightedPrefix := api.Mul(compressedPrefix, pow2(240))
	leadingRecipientX := bigEndianSum(api, recipientPubkey[1:31])
	agreement.RecipientLo = api.Add(weightedPrefix, leadingRecipientX)
	agreement.RecipientHi = bigEndianSum(api, recipientPubkey[31:33])

	// 3. Constrain the shared point and derive the ephemeral public point.
	scalar := c.parseScalar(ephemeralSecretKey)
	shared := c.scalarMulCheckedAt(recipient, scalar)

	ephemeral := c.scalarMulBaseAt(scalar)
	ephemeralXLimbs := c.canonicalLimbs(ephemeral.X)
	ephemeralYLimbs := c.canonicalLimbs(ephemeral.Y)
	agreement.EphemeralLo, agreement.EphemeralHi = c.compressedPacking(ephemeralXLimbs, ephemeralYLimbs, limbBits)

	// 4. Pack the canonical shared x-coordinate as 31 bytes plus one byte.
	sharedX := c.canonicalLimbs(shared.X)
	high, low := c.splitLowBits(sharedX[0], 8, limbBits)
	agreement.SharedLo = packAbove(api, high, sharedX, 8, limbBits)
	agreement.SharedHi = low
	return agreement
}

func (c *curve) fieldLimbs(bytes []frontend.Variable) []frontend.Variable {
	api := c.api
	bytesPerLimb := c.layout.LimbBits / 8
	var limbs []frontend.Variable
	for end := len(bytes); end > 0; end -= bytesPerLimb {
		start := max(0, end-bytesPerLimb)
		limbBytes := bytes[start:end]
		limbs = append(limbs, bigEndianSum(api, limbBytes))
	}
	return limbs
}

func bigEndianSum(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	sum := frontend.Variable(0)
	for _, byteValue := range bytes {
		sum = api.Add(api.Mul(sum, 256), byteValue)
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

// compressedPacking encodes (2 + y parity) || x as a 31-byte field and a
// two-byte field. Its inputs must already be canonical coordinate limbs.
func (c *curve) compressedPacking(xLimbs, yLimbs []frontend.Variable, limbBits int) (lo, hi frontend.Variable) {
	if abstractor.Extracting(c.api) {
		packed := abstractor.Call1(c.api, CompressedPacking{XLimbs: xLimbs, YLimbs: yLimbs, LimbBits: limbBits})
		return packed[0], packed[1]
	}
	return c.compressedPackingConstrained(xLimbs, yLimbs, limbBits)
}

func (c *curve) compressedPackingConstrained(xLimbs, yLimbs []frontend.Variable, limbBits int) (lo, hi frontend.Variable) {
	api := c.api
	_, parity := c.splitLowBits(yLimbs[0], 1, limbBits)
	high, low := c.splitLowBits(xLimbs[0], 16, limbBits)
	compressedPrefix := api.Add(2, parity)
	weightedPrefix := api.Mul(compressedPrefix, pow2(240))
	leadingX := packAbove(api, high, xLimbs, 16, limbBits)
	lo = api.Add(weightedPrefix, leadingX)
	return lo, low
}
