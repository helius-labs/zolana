// Package x25519 implements RFC 7748 key agreement in BN254 circuits.
package x25519

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/shortladder"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/x25519/internal/shortchecker"
)

// prime returns a fresh Curve25519 base-field modulus for circuit construction.
var prime = shortladder.Prime

var defaultLayout = emfield.Layout{NbLimbs: 7, LimbBits: 37, PieceBits: 10}

// ECDH clamps scalar, masks the high bit of peer, and returns the canonical
// little-endian shared secret. Noncanonical peer encodings and twist points
// are accepted. All-zero shared secrets are rejected, as in crypto/ecdh.
// Both inputs are constrained to bytes. No hashing or KDF is performed.
func ECDH(api frontend.API, scalar, peer [32]frontend.Variable) [32]frontend.Variable {
	return ecdh(api, scalar, peer, defaultLayout)
}

// ecdh proves multiplication by the clamped scalar in the chosen layout.
// BN254 and the bounded limb representations are required by the arithmetic
// checks. Peer aliases and twist points are accepted as required by RFC 7748.
func ecdh(api frontend.API, scalar, peer [32]frontend.Variable, lay emfield.Layout) [32]frontend.Variable {
	// 1. Require the native field used by all packing and carry bounds.
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		panic("x25519: BN254 native field required")
	}
	f := emfield.NewFor(api, prime(), lay)
	var shared *emfield.Element
	// 2. Bound every input byte before discarding clamped or ignored bits.
	scalarValues, scalarWidths := make([]frontend.Variable, 32), make([]int, 32)
	peerValues, peerWidths := make([]frontend.Variable, 32), make([]int, 32)
	for i := range scalar {
		scalarValues[i] = scalar[i]
		scalarWidths[i] = 8
		peerValues[i] = peer[i]
		peerWidths[i] = 8
	}
	// Clear the low three scalar bits by packing k/8 and force bit 254 to one.
	scalarValues[0], _ = splitByte(api, f, scalar[0], 3, 8)
	scalarWidths[0] = 5
	_, top := splitByte(api, f, scalar[31], 6, 8)
	scalarValues[31] = api.Add(top, 64)
	scalarWidths[31] = 7
	_, peerValues[31] = splitByte(api, f, peer[31], 7, 8)
	peerWidths[31] = 7
	for i := 1; i < 31; i++ {
		f.RangeChecker().Check(scalar[i], 8)
	}
	for i := 0; i < 31; i++ {
		f.RangeChecker().Check(peer[i], 8)
	}
	// 3. Pack s in [2^251,2^252) and u below 2^255, then prove [s]([8]P).
	s := packSegments(api, f, scalarValues, scalarWidths)
	u := packSegments(api, f, peerValues, peerWidths)
	shared = shortchecker.MultiplyScalar(api, f, u, s)

	// 4. Require the unique representative below p before byte serialization.
	f.AssertCanonical(shared)
	return outputBytes(api, f, shared)
}
