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

// P256MessageDigest returns the full SHA-256 digest of private_tx_hash — the
// ECDSA message the P256 owner signature is checked against. Unlike Sha256BE
// used elsewhere, the most-significant byte is NOT zeroed: the 256-bit digest is
// carried into the circuit as two 128-bit limbs (see P256MessageLimbs) so it can
// exceed the BN254 modulus.
func P256MessageDigest(privateTxHash *big.Int) ([32]byte, error) {
	if err := validateFieldElement("private_tx_hash", privateTxHash); err != nil {
		return [32]byte{}, fmt.Errorf("spp: P256 message digest: %w", err)
	}
	var privateTxHashBytes [32]byte
	privateTxHash.FillBytes(privateTxHashBytes[:])
	return sha256.Sum256(privateTxHashBytes[:]), nil
}

// P256MessageLimbs splits a 32-byte digest into its big-endian high (bytes
// 0..16) and low (bytes 16..32) 128-bit halves, matching the circuit's
// low-then-high bit reconstruction.
func P256MessageLimbs(digest [32]byte) (low, high *big.Int) {
	high = new(big.Int).SetBytes(digest[0:16])
	low = new(big.Int).SetBytes(digest[16:32])
	return low, high
}

// P256MessageHashField folds the digest limbs into the single field element
// bound by the public-input hash: Poseidon(low, high). On the Solana-only rail
// both limbs are 0, so this is Poseidon(0, 0).
func P256MessageHashField(low, high *big.Int) (*big.Int, error) {
	value, err := poseidon.HashWithT(3, []*big.Int{low, high})
	if err != nil {
		return nil, fmt.Errorf("spp: P256 message hash field: %w", err)
	}
	return value, nil
}

// SignedToField maps a signed integer into BN254 Fr.
func SignedToField(value *big.Int) *big.Int {
	return new(big.Int).Mod(value, poseidon.Modulus)
}

func validateFieldElement(name string, value *big.Int) error {
	return poseidon.ValidateField(name, value)
}
