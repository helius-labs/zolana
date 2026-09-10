package protocol

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
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

// Owner identity tags (spec: Fixed-byte proof-input encoding). An owner
// identity is hash_bytes_33(tag || key bytes), so a P256 x-coordinate and a
// Solana key with the same bytes have distinct identities, and neither can
// equal the untagged hash_bytes_33 viewing-key commitment (the tags avoid the
// SEC1 prefixes 0x02, 0x03, 0x04). The circuits package cannot import host code,
// so gadget.P256OwnerTag mirrors P256OwnerTag; gadget/owner_identity_test.go
// pins the two equal. No circuit hashes a Solana identity: SPP supplies it.
const (
	// SolanaOwnerTag is 'S'.
	SolanaOwnerTag = 0x53
	// P256OwnerTag is 'P'.
	P256OwnerTag = 0x50
)

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

// p256X returns the x-coordinate of a validated SEC1-compressed P256 key.
func p256X(compressed []byte) ([32]byte, error) {
	var xBytes [32]byte
	if len(compressed) != 33 {
		return xBytes, fmt.Errorf("expected 33-byte compressed P256 public key, got %d", len(compressed))
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		return xBytes, fmt.Errorf("invalid compressed P256 public-key prefix 0x%02x", compressed[0])
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil || y == nil {
		return xBytes, fmt.Errorf("invalid compressed P256 public key")
	}
	x.FillBytes(xBytes[:])
	return xBytes, nil
}

// OwnerPkField is the owner identity of a P256 key: the parity-free
// hash_bytes_33(P256OwnerTag || x), mirroring gadget.P256OwnerIdentity.
func OwnerPkField(compressed []byte) (*big.Int, error) {
	x, err := p256X(compressed)
	if err != nil {
		return nil, fmt.Errorf("spp: P256 owner pk_field: %w", err)
	}
	h, err := HashBytes(append([]byte{P256OwnerTag}, x[:]...))
	if err != nil {
		return nil, fmt.Errorf("spp: P256 owner pk_field: %w", err)
	}
	return h, nil
}

// P256PkField is the viewing-key commitment:
// Poseidon(y_is_odd, HashBytes(x)). It is not an identity, so x stays untagged.
func P256PkField(compressed []byte) (*big.Int, error) {
	x, err := p256X(compressed)
	if err != nil {
		return nil, fmt.Errorf("spp: P256 x hash: %w", err)
	}
	xHash, err := HashBytes(x[:])
	if err != nil {
		return nil, fmt.Errorf("spp: P256 x hash: %w", err)
	}
	h, err := poseidon.Hash([]*big.Int{
		new(big.Int).SetUint64(uint64(compressed[0] & 1)),
		xHash,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: P256 viewing pk_field: %w", err)
	}
	return h, nil
}
