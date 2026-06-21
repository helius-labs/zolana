package p256

import (
	"github.com/consensys/gnark/frontend"
)

// ScalarMulGenerator computes scalar * G where G is the P-256 generator point.
// scalar is a 32-byte big-endian scalar.
// Returns the result as a 65-byte uncompressed public key.
func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [65]frontend.Variable {
	curve := newP256Curve(api)

	// Convert scalar bytes to a scalar field element using multi-limb decomposition
	scalarElem := bytesToEmulatedFr(api, scalar[:])

	// Perform scalar multiplication with generator
	result := curve.ScalarMulBase(scalarElem)

	// Convert result back to bytes
	return pointToBytes(api, curve, result)
}

// ECDH computes the ECDH shared secret: x-coordinate of (ephemeralPrivKey * recipientPubKey).
// Returns the 32-byte x-coordinate of the result point.
func ECDH(api frontend.API, ephemeralPrivKey [32]frontend.Variable, recipientPubKey [65]frontend.Variable) [32]frontend.Variable {
	// Compute scalar multiplication
	resultPoint := ScalarMul(api, ephemeralPrivKey, recipientPubKey)

	// Return the x-coordinate (bytes 1-32 of the uncompressed point)
	var xCoord [32]frontend.Variable
	for i := 0; i < 32; i++ {
		xCoord[i] = resultPoint[1+i]
	}
	return xCoord
}
