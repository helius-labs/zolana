package protocol

import (
	"crypto/sha256"
	"math/big"

	"zolana/prover/prover-test/poseidon"
)

// Sha256BEField hashes bytes, clears the most significant byte, and returns a BN254 field value.
func Sha256BEField(data ...[]byte) *big.Int {
	hasher := sha256.New()
	for _, item := range data {
		hasher.Write(item)
	}
	sum := hasher.Sum(nil)
	sum[0] = 0
	return new(big.Int).SetBytes(sum)
}

// SignedToField maps a signed integer into BN254 Fr.
func SignedToField(value *big.Int) *big.Int {
	return new(big.Int).Mod(value, poseidon.Modulus)
}

func validateFieldElement(name string, value *big.Int) error {
	return poseidon.ValidateField(name, value)
}
