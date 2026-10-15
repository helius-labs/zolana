// Package x25519 implements RFC 7748 key agreement in BN254 circuits.
package x25519

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/x25519/internal/shortchecker"
)

func prime() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
}

var defaultLayout = emfield.Layout{NbLimbs: 7, LimbBits: 37, PieceBits: 10, Lookups: true}

// ECDH clamps scalar, masks the high bit of peer, and returns the canonical
// little-endian shared secret. Noncanonical peer encodings and twist points
// are accepted. All-zero shared secrets are rejected, as in crypto/ecdh.
// Both inputs are constrained to bytes. No hashing or KDF is performed.
func ECDH(api frontend.API, scalar, peer [32]frontend.Variable) [32]frontend.Variable {
	return ECDHFor(api, scalar, peer, true)
}

// ECDHFor selects lookup or Boolean range checks for the same relation.
func ECDHFor(api frontend.API, scalar, peer [32]frontend.Variable, lookups bool) [32]frontend.Variable {
	lay := defaultLayout
	if !lookups {
		lay = emfield.PlainLayout
	}
	return ecdh(api, scalar, peer, lay)
}

func ecdh(api frontend.API, scalar, peer [32]frontend.Variable, lay emfield.Layout) [32]frontend.Variable {
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		panic("x25519: BN254 native field required")
	}
	f := emfield.NewFor(api, prime(), lay)
	var shared *emfield.Element
	if lay.Lookups {
		scalarValues, scalarWidths := make([]frontend.Variable, 32), make([]int, 32)
		peerValues, peerWidths := make([]frontend.Variable, 32), make([]int, 32)
		for i := range scalar {
			scalarValues[i] = scalar[i]
			scalarWidths[i] = 8
			peerValues[i] = peer[i]
			peerWidths[i] = 8
		}
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
		s := packSegments(api, f, scalarValues, scalarWidths)
		u := packSegments(api, f, peerValues, peerWidths)
		shared = shortchecker.MultiplyScalar(api, f, u, s)
	} else {
		var k, uBits []frontend.Variable
		for i := range scalar {
			k = append(k, api.ToBinary(scalar[i], 8)...)
			uBits = append(uBits, api.ToBinary(peer[i], 8)...)
		}
		k[0], k[1], k[2], k[254], k[255] = 0, 0, 0, 1, 0
		uBits = uBits[:255] // RFC 7748 ignores the high bit before field decoding.
		limbs, widths := make([]frontend.Variable, lay.NbLimbs), f.ReducedWidths()
		for i, w := range widths {
			limbs[i] = api.FromBinary(uBits[i*lay.LimbBits : i*lay.LimbBits+w]...)
		}
		u := f.Bounded(limbs, widths) // u >= p is intentionally accepted.
		var scalarLimbs []frontend.Variable
		var scalarWidths []int
		bits := k[3:255]
		for i := 0; i < len(bits); i += lay.LimbBits {
			chunk := bits[i:min(len(bits), i+lay.LimbBits)]
			scalarLimbs = append(scalarLimbs, api.FromBinary(chunk...))
			scalarWidths = append(scalarWidths, len(chunk))
		}
		shared = shortchecker.MultiplyScalar(api, f, u, f.Bounded(scalarLimbs, scalarWidths))

	}
	f.AssertCanonical(shared)
	if lay.Lookups {
		return outputBytes(api, f, shared)
	}
	var bits []frontend.Variable
	for i, limb := range shared.Limbs() {
		bits = append(bits, api.ToBinary(limb, f.ReducedWidths()[i])...)
	}
	api.AssertIsDifferent(api.Add(0, 0, shared.Limbs()...), 0)
	bits = append(bits, 0)
	var out [32]frontend.Variable
	for i := range out {
		out[i] = api.FromBinary(bits[8*i : 8*i+8]...)
	}
	return out
}
