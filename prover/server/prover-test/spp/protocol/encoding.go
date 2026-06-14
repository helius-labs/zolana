package protocol

import (
	"crypto/sha256"
	"fmt"
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

// P256MessageHash returns Sha256BE(private_tx_hash) — the ECDSA message digest
// the P256 owner signature is checked against (spec: private_tx_hash_digest).
// Sha256BE is SHA-256 with the most-significant byte zeroed (digest[1..32]).
func P256MessageHash(privateTxHash *big.Int) (*big.Int, error) {
	if err := validateFieldElement("private_tx_hash", privateTxHash); err != nil {
		return nil, fmt.Errorf("spp: P256 message hash: %w", err)
	}
	var privateTxHashBytes [32]byte
	privateTxHash.FillBytes(privateTxHashBytes[:])
	return Sha256BEField(privateTxHashBytes[:]), nil
}

// SignedToField maps a signed integer into BN254 Fr.
func SignedToField(value *big.Int) *big.Int {
	return new(big.Int).Mod(value, poseidon.Modulus)
}

func validateFieldElement(name string, value *big.Int) error {
	return poseidon.ValidateField(name, value)
}
