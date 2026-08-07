// Package p256 implements P-256 elliptic curve operations for gnark. Uses
// 65-byte uncompressed public keys (0x04 || x || y) and 32-byte big-endian
// scalars.
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

// bytesToEmulated converts 32 big-endian bytes into an emulated element of T
// using 4 limbs of 64 bits each in little-endian limb order, so bytes[0..7]
// become limb[3].
func bytesToEmulated[T emulated.FieldParams](api frontend.API, bytes []frontend.Variable) *emulated.Element[T] {
	limbs := make([]frontend.Variable, 4)
	limbs[3] = bytesToLimb(api, bytes[0:8])
	limbs[2] = bytesToLimb(api, bytes[8:16])
	limbs[1] = bytesToLimb(api, bytes[16:24])
	limbs[0] = bytesToLimb(api, bytes[24:32])

	field, err := emulated.NewField[T](api)
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
		// In each byte the MSB is bits[i*8] and the LSB is bits[i*8+7]
		// FromBinary expects LSB first, so reverse the bit order within the byte
		byteBits := make([]frontend.Variable, 8)
		for j := 0; j < 8; j++ {
			byteBits[j] = bits[i*8+7-j]
		}
		bytes[i] = api.FromBinary(byteBits...)
	}
	return bytes
}

func newP256Curve(api frontend.API) *sw_emulated.Curve[emulated.P256Fp, emulated.P256Fr] {
	params := sw_emulated.GetP256Params()
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](api, params)
	if err != nil {
		panic(err)
	}
	return curve
}

// parsePublicKey parses a 65-byte uncompressed public key into an AffinePoint.
// The public key format is 0x04 || x (32 bytes) || y (32 bytes).
func parsePublicKey(api frontend.API, publicKey [65]frontend.Variable) *sw_emulated.AffinePoint[emulated.P256Fp] {
	xBytes := publicKey[1:33]
	yBytes := publicKey[33:65]

	xElem := bytesToEmulated[emulated.P256Fp](api, xBytes)
	yElem := bytesToEmulated[emulated.P256Fp](api, yBytes)

	return &sw_emulated.AffinePoint[emulated.P256Fp]{
		X: *xElem,
		Y: *yElem,
	}
}

// limbToBytes converts a 64-bit limb (native field variable) into 8 big-endian bytes.
func limbToBytes(api frontend.API, limb frontend.Variable) [8]frontend.Variable {
	bits := api.ToBinary(limb, 64)

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
// Reduces to canonical form first so the byte image is unique.
func emulatedFpToBytes(api frontend.API, elem *emulated.Element[emulated.P256Fp]) [32]frontend.Variable {
	field, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		panic(err)
	}
	reduced := field.Reduce(elem)

	var result [32]frontend.Variable
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

// PointOnCurve constrains publicKey to be a point on the P-256 curve.
func PointOnCurve(api frontend.API, publicKey [65]frontend.Variable) {
	curve := newP256Curve(api)
	point := parsePublicKey(api, publicKey)
	curve.AssertIsOnCurve(point)
}

// PointFromBytes extracts the x and y coordinate bytes from an uncompressed
// public key. Returns (x[32], y[32]).
func PointFromBytes(api frontend.API, publicKey [65]frontend.Variable) ([32]frontend.Variable, [32]frontend.Variable) {
	var x, y [32]frontend.Variable
	for i := 0; i < 32; i++ {
		x[i] = publicKey[1+i]
		y[i] = publicKey[33+i]
	}
	return x, y
}

// ScalarMul computes scalar * point on the P-256 curve.
// scalar is a 32-byte big-endian scalar.
// pointIn is a 65-byte uncompressed public key.
// Returns the result as a 65-byte uncompressed public key.
func ScalarMul(api frontend.API, scalar [32]frontend.Variable, pointIn [65]frontend.Variable) [65]frontend.Variable {
	curve := newP256Curve(api)

	point := parsePublicKey(api, pointIn)
	scalarElem := bytesToEmulated[emulated.P256Fr](api, scalar[:])
	result := curve.ScalarMul(point, scalarElem)
	return pointToBytes(api, curve, result)
}
