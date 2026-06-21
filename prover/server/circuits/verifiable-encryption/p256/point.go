// Package p256 implements P-256 elliptic curve operations for gnark.
//
// Ported verbatim from confidential-transfers
// (circuits/encryption-utils/p256). Uses 65-byte uncompressed public keys
// (0x04 || x || y) and 32-byte big-endian scalars.
package p256

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// bytesToLimb converts 8 big-endian bytes (frontend.Variables) into a single
// 64-bit native field value.
// value = b[0]*2^56 + b[1]*2^48 + ... + b[7]
func bytesToLimb(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for i := 0; i < 8; i++ {
		result = api.Add(api.Mul(result, 256), bytes[i])
	}
	return result
}

// bytesToEmulatedFp converts 32 big-endian bytes into an emulated P256Fp element
// using 4 limbs of 64 bits each (little-endian limb order).
func bytesToEmulatedFp(api frontend.API, bytes []frontend.Variable) *emulated.Element[emulated.P256Fp] {
	// P256Fp uses 4 limbs of 64 bits.
	// Limbs are in little-endian order: limb[0] = least significant 64 bits.
	// bytes[0..7] = most significant 64 bits = limb[3]
	// bytes[8..15] = limb[2]
	// bytes[16..23] = limb[1]
	// bytes[24..31] = limb[0]
	limbs := make([]frontend.Variable, 4)
	limbs[3] = bytesToLimb(api, bytes[0:8])
	limbs[2] = bytesToLimb(api, bytes[8:16])
	limbs[1] = bytesToLimb(api, bytes[16:24])
	limbs[0] = bytesToLimb(api, bytes[24:32])

	field, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		panic(err)
	}
	return field.NewElement(limbs)
}

// bytesToEmulatedFr converts 32 big-endian bytes into an emulated P256Fr element
// using 4 limbs of 64 bits each (little-endian limb order).
func bytesToEmulatedFr(api frontend.API, bytes []frontend.Variable) *emulated.Element[emulated.P256Fr] {
	limbs := make([]frontend.Variable, 4)
	limbs[3] = bytesToLimb(api, bytes[0:8])
	limbs[2] = bytesToLimb(api, bytes[8:16])
	limbs[1] = bytesToLimb(api, bytes[16:24])
	limbs[0] = bytesToLimb(api, bytes[24:32])

	field, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		panic(err)
	}
	return field.NewElement(limbs)
}

// bitsToBytes converts MSB-first bits to big-endian bytes.
// bits must be a multiple of 8 in length.
func bitsToBytes(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	nBytes := len(bits) / 8
	bytes := make([]frontend.Variable, nBytes)
	for i := 0; i < nBytes; i++ {
		// Each byte: MSB is bits[i*8], LSB is bits[i*8+7]
		// FromBinary expects LSB first, so reverse the bit order within the byte
		byteBits := make([]frontend.Variable, 8)
		for j := 0; j < 8; j++ {
			byteBits[j] = bits[i*8+7-j]
		}
		bytes[i] = api.FromBinary(byteBits...)
	}
	return bytes
}

// newP256Curve creates a new P-256 curve instance for the circuit.
func newP256Curve(api frontend.API) *sw_emulated.Curve[emulated.P256Fp, emulated.P256Fr] {
	params := sw_emulated.GetP256Params()
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](api, params)
	if err != nil {
		panic(err)
	}
	return curve
}

// ParsePublicKey parses a 65-byte uncompressed public key (0x04 || x || y) into
// an emulated AffinePoint. It does not assert the point is on the curve; callers
// that need that guarantee use PointOnCurve.
func ParsePublicKey(api frontend.API, publicKey [65]frontend.Variable) *sw_emulated.AffinePoint[emulated.P256Fp] {
	return parsePublicKey(api, publicKey)
}

// parsePublicKey parses a 65-byte uncompressed public key into an AffinePoint.
// The public key format is 0x04 || x (32 bytes) || y (32 bytes).
func parsePublicKey(api frontend.API, publicKey [65]frontend.Variable) *sw_emulated.AffinePoint[emulated.P256Fp] {
	// Extract x and y coordinate bytes
	xBytes := publicKey[1:33]
	yBytes := publicKey[33:65]

	// Convert bytes to emulated field elements using multi-limb decomposition
	xElem := bytesToEmulatedFp(api, xBytes)
	yElem := bytesToEmulatedFp(api, yBytes)

	return &sw_emulated.AffinePoint[emulated.P256Fp]{
		X: *xElem,
		Y: *yElem,
	}
}

// limbToBytes converts a 64-bit limb (native field variable) into 8 big-endian bytes.
func limbToBytes(api frontend.API, limb frontend.Variable) [8]frontend.Variable {
	// Decompose the limb into 64 bits (LSB first)
	bits := api.ToBinary(limb, 64)

	// Convert to 8 bytes in big-endian order
	// byte 0 = MSB = bits[56..63], byte 7 = LSB = bits[0..7]
	var result [8]frontend.Variable
	for i := 0; i < 8; i++ {
		// byte i = bits from [(7-i)*8 .. (7-i)*8 + 7], reversed for FromBinary (LSB first)
		byteBits := make([]frontend.Variable, 8)
		for j := 0; j < 8; j++ {
			byteBits[j] = bits[(7-i)*8+j]
		}
		result[i] = api.FromBinary(byteBits...)
	}
	return result
}

// emulatedFpToBytes converts a P256Fp emulated element to 32 big-endian bytes.
// The element must be reduced (canonical form) before calling.
func emulatedFpToBytes(api frontend.API, elem *emulated.Element[emulated.P256Fp]) [32]frontend.Variable {
	// Element has 4 limbs in little-endian order, each 64 bits
	// limb[0] = least significant, limb[3] = most significant
	// Reduce to canonical form first
	field, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		panic(err)
	}
	reduced := field.Reduce(elem)

	var result [32]frontend.Variable
	// limb[3] -> bytes[0..7] (MSB), limb[2] -> bytes[8..15], etc.
	for limbIdx := 0; limbIdx < 4; limbIdx++ {
		byteOffset := (3 - limbIdx) * 8
		limbBytes := limbToBytes(api, reduced.Limbs[limbIdx])
		for j := 0; j < 8; j++ {
			result[byteOffset+j] = limbBytes[j]
		}
	}
	return result
}

// pointToBytes converts an AffinePoint back to 65-byte uncompressed format.
// Returns [0x04 || x (32 bytes) || y (32 bytes)].
func pointToBytes(api frontend.API, curve *sw_emulated.Curve[emulated.P256Fp, emulated.P256Fr], point *sw_emulated.AffinePoint[emulated.P256Fp]) [65]frontend.Variable {
	xBytes := emulatedFpToBytes(api, &point.X)
	yBytes := emulatedFpToBytes(api, &point.Y)

	var result [65]frontend.Variable
	result[0] = frontend.Variable(0x04)
	for i := 0; i < 32; i++ {
		result[1+i] = xBytes[i]
		result[33+i] = yBytes[i]
	}
	return result
}

// PointOnCurve verifies that the given uncompressed public key represents a
// point on the P-256 curve. Panics/fails the constraint if the point is not
// on the curve.
func PointOnCurve(api frontend.API, publicKey [65]frontend.Variable) {
	curve := newP256Curve(api)
	point := parsePublicKey(api, publicKey)
	curve.AssertIsOnCurve(point)
}

// ScalarMul computes scalar * point on the P-256 curve.
// scalar is a 32-byte big-endian scalar.
// pointIn is a 65-byte uncompressed public key.
// Returns the result as a 65-byte uncompressed public key.
func ScalarMul(api frontend.API, scalar [32]frontend.Variable, pointIn [65]frontend.Variable) [65]frontend.Variable {
	curve := newP256Curve(api)

	// Parse the input point
	point := parsePublicKey(api, pointIn)

	// Convert scalar bytes to a scalar field element using multi-limb decomposition
	scalarElem := bytesToEmulatedFr(api, scalar[:])

	// Perform scalar multiplication
	result := curve.ScalarMul(point, scalarElem)

	// Convert result back to bytes
	return pointToBytes(api, curve, result)
}
