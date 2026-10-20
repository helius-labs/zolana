package protocol

import (
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
)

// Merge output ciphertext domain tags (mirror circuits/spp_merge/shared).
const (
	// MergeOutputKeyDomain is the ASCII tag "TMOK".
	MergeOutputKeyDomain = 0x544d4f4b
	// MergeOutputCiphertextDomain is the ASCII tag "TMOC".
	MergeOutputCiphertextDomain = 0x544d4f43
)

// MintChunks splits a mint into its hash_bytes_32 chunks: bytes 0..31 and
// byte 31. HashChain over them is AssetField(mint).
func MintChunks(mint [32]byte) [2]*big.Int {
	return [2]*big.Int{
		new(big.Int).SetBytes(mint[:hashBytesChunkSize]),
		new(big.Int).SetBytes(mint[hashBytesChunkSize:]),
	}
}

// MergeOutputKey is the per-merge key: Poseidon("TMOK", nullifier_secret,
// first_nullifier).
func MergeOutputKey(nullifierSecret, firstNullifier *big.Int) (*big.Int, error) {
	key, err := poseidon.Hash([]*big.Int{
		big.NewInt(MergeOutputKeyDomain), nullifierSecret, firstNullifier,
	})
	if err != nil {
		return nil, fmt.Errorf("merge output key: %w", err)
	}
	return key, nil
}

// MergeOutputCiphertext encrypts [amount, mint chunks] under MergeOutputKey with
// the per-proof salt as the pad nonce: element i plus Poseidon("TMOC", key,
// salt, i).
func MergeOutputCiphertext(
	nullifierSecret, firstNullifier, salt, amount *big.Int,
	mint [32]byte,
) ([]*big.Int, error) {
	key, err := MergeOutputKey(nullifierSecret, firstNullifier)
	if err != nil {
		return nil, err
	}
	chunks := MintChunks(mint)
	plaintext := []*big.Int{amount, chunks[0], chunks[1]}
	ciphertext := make([]*big.Int, len(plaintext))
	for i, element := range plaintext {
		pad, err := poseidon.Hash([]*big.Int{
			big.NewInt(MergeOutputCiphertextDomain), key, salt, big.NewInt(int64(i)),
		})
		if err != nil {
			return nil, fmt.Errorf("merge output pad %d: %w", i, err)
		}
		ciphertext[i] = new(big.Int).Mod(new(big.Int).Add(element, pad), poseidon.Modulus)
	}
	return ciphertext, nil
}
