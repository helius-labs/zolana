package x25519

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

// ScalarMulGenerator derives a canonical, nonzero X25519 public key.
// It constrains all input bytes and applies RFC 7748 clamping. It does not
// prove that the private scalar was sampled randomly or kept secret.
func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [32]frontend.Variable {
	// 1. Require BN254 and choose the proven fixed-base limb layout.
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		panic("x25519: BN254 native field required")
	}
	lay := defaultLayout
	// Fixed-base constant selection favors six 43-bit limbs. Keep the raw
	// checker's piece width so both operations share one range-check table.
	lay.NbLimbs, lay.LimbBits = 6, 43
	f := nonnative.NewFor(api, prime(), lay)
	// 2. Bound every input byte, including bits discarded by clamping.
	var bits []frontend.Variable
	for _, b := range scalar {
		bits = append(bits, api.ToBinary(b, 8)...)
	}
	// 3. Set bit 254 and pass k/8, omitting low bits 0..2 and high bit 255.
	bits[254] = 1
	result := multiplyBase(api, f, bits[3:255])
	// 4. Enforce the unique field encoding and nonzero public key.
	f.AssertCanonical(result)
	return outputBytes(api, f, result)
}
