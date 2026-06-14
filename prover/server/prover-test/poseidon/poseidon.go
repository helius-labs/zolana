// Package poseidon is a thin host-side shim over iden3's BN254 Poseidon. It
// exists so the SPP/test code that used the old light-prover `prover/poseidon`
// needs no call-site changes. iden3 is now the single Poseidon source: host
// hashing goes through this shim; the in-circuit gadget (circuits/poseidon)
// links iden3's constants via go:linkname. The two therefore match by
// construction (both are circomlib BN254 HADES, domain_tag = 0).
package poseidon

import (
	"fmt"
	"math/big"

	iden3 "github.com/iden3/go-iden3-crypto/poseidon"
)

// Modulus is the BN254 scalar field (Fr) modulus.
var Modulus, _ = new(big.Int).SetString(
	"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)

const (
	// MinWidth and MaxWidth are the inclusive bounds on the supported width t.
	MinWidth = 2
	MaxWidth = 14
)

// Hash computes Poseidon(domain_tag = 0, inputs...).
func Hash(inputs []*big.Int) (*big.Int, error) {
	return HashWithT(len(inputs)+1, inputs)
}

// HashWithT computes Poseidon(domain_tag = 0, inputs...) at width t; requires
// len(inputs) == t-1.
func HashWithT(t int, inputs []*big.Int) (*big.Int, error) {
	if t < MinWidth || t > MaxWidth {
		return nil, fmt.Errorf("poseidon: unsupported width t=%d", t)
	}
	if len(inputs) != t-1 {
		return nil, fmt.Errorf("poseidon: want %d inputs for t=%d, got %d", t-1, t, len(inputs))
	}
	// iden3.Hash panics on a nil or out-of-field input; validate up front so
	// every caller (UtxoHash, Nullifier, ...) gets an error instead.
	for i, input := range inputs {
		if err := ValidateField(fmt.Sprintf("input[%d]", i), input); err != nil {
			return nil, fmt.Errorf("poseidon: %w", err)
		}
	}
	return iden3.Hash(inputs)
}

// ValidateField checks that value is a canonical BN254 Fr element.
func ValidateField(name string, value *big.Int) error {
	if value == nil {
		return fmt.Errorf("%s is nil", name)
	}
	if value.Sign() < 0 {
		return fmt.Errorf("%s is negative", name)
	}
	if value.Cmp(Modulus) >= 0 {
		return fmt.Errorf("%s exceeds BN254 field modulus", name)
	}
	return nil
}
