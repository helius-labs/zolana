package x25519

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

// multiply accepts bit-decomposed scalar input and applies X25519 clamping.
func multiply(api frontend.API, f *nonnative.Field, u *nonnative.Element, k []frontend.Variable) *nonnative.Element {
	bits := append([]frontend.Variable{}, k[3:254]...)
	bits = append(bits, 1)
	var limbs []frontend.Variable
	var widths []int
	for i := 0; i < len(bits); i += f.Layout().LimbBits {
		chunk := bits[i:min(len(bits), i+f.Layout().LimbBits)]
		limbs = append(limbs, api.FromBinary(chunk...))
		widths = append(widths, len(chunk))
	}
	return multiplyScalar(api, f, u, f.Bounded(limbs, widths))
}
