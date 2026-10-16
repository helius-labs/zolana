// Package p256 implements P-256 elliptic curve operations for gnark.
//
// Retained from confidential-transfers
// (circuits/encryption-utils/p256). Uses 65-byte uncompressed public keys
// (0x04 || x || y) and 32-byte big-endian scalars.
package p256

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// GroupOrder returns a fresh copy of P-256's prime scalar order. Callers can
// use it to enforce a unique scalar encoding without mutating shared constants.
func GroupOrder() *big.Int {
	return new(big.Int).Set(emulated.P256Fr{}.Modulus())
}

// bytesToLimb packs eight big-endian bytes into a 64-bit native value.
// The caller must range-check each byte first. A limb bound alone would not
// exclude aliases between adjacent out-of-range byte elements.
func bytesToLimb(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for i := 0; i < 8; i++ {
		result = api.Add(api.Mul(result, 256), bytes[i])
	}
	return result
}

// bytesToEmulatedFp packs 32 big-endian bytes into four little-endian limbs.
// The caller must constrain each byte. This conversion does not establish a
// canonical coordinate below p or validate membership of a point.
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

	// Construct the emulated coordinate from the packed limbs.
	field, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		panic(err)
	}
	return field.NewElement(limbs)
}

// bytesToEmulatedFr packs 32 big-endian scalar bytes and rejects zero modulo n.
// The caller must constrain individual bytes and any required scalar<n bound.
// Rejecting multiples of n excludes the point at infinity for a valid peer.
func bytesToEmulatedFr(api frontend.API, bytes []frontend.Variable) *emulated.Element[emulated.P256Fr] {
	// 1. Pack caller-constrained bytes into little-endian 64-bit limbs.
	limbs := make([]frontend.Variable, 4)
	limbs[3] = bytesToLimb(api, bytes[0:8])
	limbs[2] = bytesToLimb(api, bytes[8:16])
	limbs[1] = bytesToLimb(api, bytes[16:24])
	limbs[0] = bytesToLimb(api, bytes[24:32])

	// 2. Construct the scalar field element and exclude zero modulo n.
	field, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		panic(err)
	}
	elem := field.NewElement(limbs)
	// 0 and n map to the point at infinity, a key no host ECDH can match.
	field.AssertIsDifferent(elem, field.Zero())
	return elem
}

// bitsToBytes packs MSB-first bits into big-endian bytes. The input length
// must be a multiple of eight. FromBinary constrains each consumed bit,
// preventing non-Boolean representations of the returned bytes.
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

// newP256Curve constructs the gnark curve with fixed P-256 parameters.
// Construction failure aborts compilation. No witness can select another curve.
func newP256Curve(api frontend.API) *sw_emulated.Curve[emulated.P256Fp, emulated.P256Fr] {
	params := sw_emulated.GetP256Params()
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](api, params)
	if err != nil {
		panic(err)
	}
	return curve
}

// ParsePublicKey extracts coordinates from the 65-element SEC1-shaped input.
// It performs no per-byte, prefix, canonicality, on-curve or nonidentity checks.
// Callers must supply those guarantees before treating the result as a key.
func ParsePublicKey(api frontend.API, publicKey [65]frontend.Variable) *sw_emulated.AffinePoint[emulated.P256Fp] {
	return parsePublicKey(api, publicKey)
}

// parsePublicKey converts the coordinate slices into emulated field elements.
// It inherits the caller-validation requirements of ParsePublicKey and ignores
// the prefix. Parsing alone is not public-key validation.
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

// limbToBytes splits a limb into eight big-endian bytes. The 64-bit binary
// decomposition both bounds the input and makes the encoding unique.
func limbToBytes(api frontend.API, limb frontend.Variable) [8]frontend.Variable {
	// Decompose the limb into 64 bits (LSB first)
	bits := api.ToBinary(limb, 64)

	// Convert to 8 bytes in big-endian order
	// byte 0 = MSB = bits[56..63], byte 7 = LSB = bits[0..7]
	var result [8]frontend.Variable
	for i := 0; i < 8; i++ {
		// Select the byte in big-endian order, keeping its internal bits LSB first.
		byteBits := make([]frontend.Variable, 8)
		for j := 0; j < 8; j++ {
			byteBits[j] = bits[(7-i)*8+j]
		}
		result[i] = api.FromBinary(byteBits...)
	}
	return result
}

// emulatedFpToBytes returns the unique 32-byte big-endian coordinate below p.
// Strict reduction is essential because x+p must not encode the same point
// as another byte string in a transcript.
func emulatedFpToBytes(api frontend.API, elem *emulated.Element[emulated.P256Fp]) [32]frontend.Variable {
	// Element has 4 limbs in little-endian order, each 64 bits
	// limb[0] = least significant, limb[3] = most significant
	// Strictly reduce before serializing to exclude alternative encodings.
	field, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		panic(err)
	}
	reduced := field.ReduceStrict(elem)

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

// pointToBytes serializes canonical coordinates with the SEC1 prefix 0x04.
// It does not validate curve membership or reject the infinity representation.
// Callers must establish those properties before exposing the result as a key.
func pointToBytes(api frontend.API, curve *sw_emulated.Curve[emulated.P256Fp, emulated.P256Fr], point *sw_emulated.AffinePoint[emulated.P256Fp]) [65]frontend.Variable {
	// 1. Strictly reduce and serialize each coordinate.
	xBytes := emulatedFpToBytes(api, &point.X)
	yBytes := emulatedFpToBytes(api, &point.Y)

	// 2. Assemble the fixed prefix and the canonical coordinate encodings.
	var result [65]frontend.Variable
	result[0] = frontend.Variable(0x04)
	for i := 0; i < 32; i++ {
		result[1+i] = xBytes[i]
		result[33+i] = yBytes[i]
	}
	return result
}

// PointOnCurve constrains the parsed coordinates with gnark's curve check.
// It does not check individual byte bounds, the prefix or canonical coordinates.
// Gnark also admits its (0,0) infinity representation, so callers needing a
// finite public key must reject that representation separately.
func PointOnCurve(api frontend.API, publicKey [65]frontend.Variable) {
	// 1. Parse the coordinates under the caller's byte and encoding contract.
	curve := newP256Curve(api)
	point := parsePublicKey(api, publicKey)
	// 2. Apply gnark's membership check, which also admits its infinity sentinel.
	curve.AssertIsOnCurve(point)
}

// ScalarMul computes scalar*point and serializes canonical result coordinates.
// The caller must supply byte-constrained inputs and a finite on-curve point.
// It does not validate an arbitrary peer. bytesToEmulatedFr rejects zero
// modulo n, while a unique scalar encoding requires a separate scalar<n check.
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

// AssertScalarInRange asserts 0 < scalar < n for 32 big-endian bytes the caller range checks.
func AssertScalarInRange(api frontend.API, scalar [32]frontend.Variable) {
	field, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		panic(err)
	}
	field.AssertIsInRange(bytesToEmulatedFr(api, scalar[:]))
}
