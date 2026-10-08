package emcurve

import (
	"github.com/consensys/gnark/frontend"
)

func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [65]frontend.Variable {
	return ScalarMulGeneratorFor(api, scalar, true)
}

func ScalarMulGeneratorFor(api frontend.API, scalar [32]frontend.Variable, lookups bool) [65]frontend.Variable {
	c := newCurveFor(api, lookups)
	result := c.scalarMulBase(c.fr.FromLimbs(c.fieldLimbs(scalar[:])))
	var out [65]frontend.Variable
	out[0] = frontend.Variable(0x04)
	copy(out[1:33], c.toBytes(result.X))
	copy(out[33:65], c.toBytes(result.Y))
	return out
}

func ECDH(api frontend.API, ephemeralPrivKey [32]frontend.Variable, recipientPubKey [65]frontend.Variable) [32]frontend.Variable {
	return ECDHFor(api, ephemeralPrivKey, recipientPubKey, true)
}

func ECDHFor(api frontend.API, ephemeralPrivKey [32]frontend.Variable, recipientPubKey [65]frontend.Variable, lookups bool) [32]frontend.Variable {
	resultPoint := ScalarMulFor(api, ephemeralPrivKey, recipientPubKey, lookups)
	var xCoord [32]frontend.Variable
	for i := 0; i < 32; i++ {
		xCoord[i] = resultPoint[1+i]
	}
	return xCoord
}
