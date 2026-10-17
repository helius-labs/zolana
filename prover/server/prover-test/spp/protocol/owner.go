package protocol

import (
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
)

func NullifierPk(nullifierSecret *big.Int) (*big.Int, error) {
	h, err := poseidon.Hash([]*big.Int{nullifierSecret})
	if err != nil {
		return nil, fmt.Errorf("spp: nullifier pk: %w", err)
	}
	return h, nil
}

func OwnerHash(ownerKeyHash, nullifierPk *big.Int) (*big.Int, error) {
	h, err := poseidon.Hash([]*big.Int{ownerKeyHash, nullifierPk})
	if err != nil {
		return nil, fmt.Errorf("spp: owner hash: %w", err)
	}
	return h, nil
}

// SolanaOwnerTag separates signing identities from untagged asset hashes.
const SolanaOwnerTag = 0x53

// SolanaPkField is the owner identity of a Solana pubkey or PDA address:
// hash_bytes_33(SolanaOwnerTag || pubkey).
func SolanaPkField(pubkey [32]byte) (*big.Int, error) {
	h, err := HashBytes(append([]byte{SolanaOwnerTag}, pubkey[:]...))
	if err != nil {
		return nil, fmt.Errorf("spp: solana pk hash: %w", err)
	}
	return h, nil
}

// AssetField encodes a mint address as the UTXO asset field: the untagged
// hash_bytes_32(mint). Assets are not identities, so they carry no owner tag;
// SOL is Address::default().
func AssetField(mint [32]byte) (*big.Int, error) {
	h, err := HashBytes(mint[:])
	if err != nil {
		return nil, fmt.Errorf("spp: asset field: %w", err)
	}
	return h, nil
}
