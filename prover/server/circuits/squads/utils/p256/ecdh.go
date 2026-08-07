package p256

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// ScalarMulGenerator computes scalar * G where G is the P-256 generator point.
// scalar is a 32-byte big-endian scalar.
// Returns the result as a 65-byte uncompressed public key.
func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [65]frontend.Variable {
	curve := newP256Curve(api)

	scalarElem := bytesToEmulated[emulated.P256Fr](api, scalar[:])
	result := curve.ScalarMulBase(scalarElem)
	return pointToBytes(api, curve, result)
}

// ECDH returns the 32-byte x-coordinate of ephemeralPrivKey * recipientPubKey.
func ECDH(api frontend.API, ephemeralPrivKey [32]frontend.Variable, recipientPubKey [65]frontend.Variable) [32]frontend.Variable {
	resultPoint := ScalarMul(api, ephemeralPrivKey, recipientPubKey)

	var xCoord [32]frontend.Variable
	for i := 0; i < 32; i++ {
		xCoord[i] = resultPoint[1+i]
	}
	return xCoord
}
