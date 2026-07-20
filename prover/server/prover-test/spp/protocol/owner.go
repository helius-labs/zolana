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

// SolanaPkField is hash_bytes over a 32-byte value (an ed25519 owner key, an
// asset mint, or a zone program address). Owner, asset, and zone fields share
// this encoding and are separated by their position in the enclosing hash.
func SolanaPkField(pubkey [32]byte) (*big.Int, error) {
	h, err := HashBytes(pubkey[:])
	if err != nil {
		return nil, fmt.Errorf("spp: solana pk hash: %w", err)
	}
	return h, nil
}

// ownerX extracts and validates the 32-byte x-coordinate of a SEC1-compressed
// P256 public key.
func ownerX(compressed []byte) ([32]byte, error) {
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

// OwnerPkField is the rail-agnostic, parity-free owner pk_field: hash_bytes(x)
// over the 32-byte x-coordinate, matching the circuit OwnerPkFieldGadget and Rust
// PublicKey::owner_pk_field. The y-parity is carried in the encrypted data, not
// the owner identity.
func OwnerPkField(compressed []byte) (*big.Int, error) {
	xBytes, err := ownerX(compressed)
	if err != nil {
		return nil, fmt.Errorf("spp: P256 owner pk_field: %w", err)
	}
	h, err := HashBytes(xBytes[:])
	if err != nil {
		return nil, fmt.Errorf("spp: P256 owner pk_field: %w", err)
	}
	return h, nil
}

// P256PkField is the VIEWING-key pk_field: hash_bytes(sec1_compressed) over the
// full 33-byte SEC1 point, matching the circuit P256PkFieldGadget. The owner key
// uses OwnerPkField instead.
func P256PkField(compressed []byte) (*big.Int, error) {
	if _, err := ownerX(compressed); err != nil {
		return nil, fmt.Errorf("spp: P256 viewing pk_field: %w", err)
	}
	h, err := HashBytes(compressed)
	if err != nil {
		return nil, fmt.Errorf("spp: P256 viewing pk_field: %w", err)
	}
	return h, nil
}
