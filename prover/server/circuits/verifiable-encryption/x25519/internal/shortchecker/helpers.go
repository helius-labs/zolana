package shortchecker

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/internal/emfield"
)

// pow2 returns a public power of two for limb weights and compile-time bounds.
// It does not introduce witness values or constraints.
func pow2(n int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n))
}

// rangeChecker returns the field's shared range checker. Its deferred lookup
// checks are part of the compiled circuit and must not be omitted.
func (c *curve) rangeChecker() *emfield.RangeChecker {
	return c.fp.RangeChecker()
}

// limbHintInputs prefixes limbs with their public radix for witness generation.
// It adds no constraints and requires the caller to establish limb bounds.
func (c *curve) limbHintInputs(limbs []frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{c.lay.LimbBits}, limbs...)
}

// limbHintValue reconstructs a host integer from unsigned little-endian limbs.
// The header is supplied by the circuit. This helper does not validate a witness.
func limbHintValue(inputs []*big.Int) *big.Int {
	// 1. Read the public radix supplied by the circuit.
	limbBits := uint(inputs[0].Uint64())
	// 2. Recompose unsigned limbs from most to least significant.
	s := new(big.Int)
	for i := len(inputs) - 1; i >= 1; i-- {
		s.Lsh(s, limbBits).Add(s, inputs[i])
	}
	return s
}
