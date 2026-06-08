package protocol

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
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

// P256MessageHash returns 0x00 || SHA256(private_tx_hash_be32)[0:31].
func P256MessageHash(privateTxHash *big.Int) (*big.Int, error) {
	if err := validateFieldElement("private_tx_hash", privateTxHash); err != nil {
		return nil, fmt.Errorf("spp: P256 message hash: %w", err)
	}
	var privateTxHashBytes [32]byte
	privateTxHash.FillBytes(privateTxHashBytes[:])
	sum := sha256.Sum256(privateTxHashBytes[:])
	var out [32]byte
	copy(out[1:], sum[:31])
	return new(big.Int).SetBytes(out[:]), nil
}

// SignedToField maps a signed integer into BN254 Fr.
func SignedToField(value *big.Int) *big.Int {
	return new(big.Int).Mod(value, poseidon.Modulus)
}

func validateFieldElement(name string, value *big.Int) error {
	return poseidon.ValidateField(name, value)
}
