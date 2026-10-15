package x25519

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/x25519/internal/shortchecker"
)

// ScalarMulGenerator derives the canonical 32-byte X25519 public key from a
// byte-constrained private scalar, including RFC 7748 clamping.
func ScalarMulGenerator(api frontend.API, scalar [32]frontend.Variable) [32]frontend.Variable {
	return ScalarMulGeneratorFor(api, scalar, true)
}

func ScalarMulGeneratorFor(api frontend.API, scalar [32]frontend.Variable, lookups bool) [32]frontend.Variable {
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		panic("x25519: BN254 native field required")
	}
	lay := defaultLayout
	// Fixed-base constant selection favors six 43-bit limbs. Keep the raw
	// checker's piece width so both operations share one range-check table.
	lay.NbLimbs, lay.LimbBits = 6, 43
	if !lookups {
		lay = emfield.PlainLayout
	}
	f := emfield.NewFor(api, prime(), lay)
	var bits []frontend.Variable
	for _, b := range scalar {
		bits = append(bits, api.ToBinary(b, 8)...)
	}
	bits[254] = 1
	result := shortchecker.MultiplyBase(api, f, bits[3:255])
	f.AssertCanonical(result)
	return outputBytes(api, f, result)
}
