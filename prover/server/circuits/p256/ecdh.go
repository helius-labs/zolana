package p256

import (
	"github.com/consensys/gnark/frontend"
)

// ScalarMulGenerator computes scalar*G as a canonical 65-byte P-256 point.
// The caller must constrain all scalar elements to bytes and, when unique
// secret encoding matters, require scalar<n. Multiples of n are rejected by
// bytesToEmulatedFr. This helper does not prove scalar entropy or secrecy.
func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [65]frontend.Variable {
	curve := newP256Curve(api)

	// Convert scalar bytes to a scalar field element using multi-limb decomposition
	scalarElem := bytesToEmulatedFr(api, scalar[:])

	// Perform scalar multiplication with generator
	result := curve.ScalarMulBase(scalarElem)

	// Convert result back to bytes
	return pointToBytes(api, curve, result)
}

// ECDH returns the canonical 32-byte big-endian X coordinate of scalar*peer.
// This is the retained P-256 viewing-key primitive, with no KDF. It assumes
// byte-constrained inputs, a finite on-curve peer and a scalar nonzero modulo n.
// ScalarMul rejects zero scalars but does not validate an arbitrary peer key.
// The current counter caller supplies a point from ScalarMulGenerator. Any
// caller accepting external keys must validate byte bounds, SEC1 prefix,
// canonical coordinates, on-curve membership and nonidentity before use.
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
