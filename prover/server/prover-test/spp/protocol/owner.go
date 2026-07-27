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

func SolanaPkField(pubkey [32]byte) (*big.Int, error) {
	h, err := HashBytes(pubkey[:])
	if err != nil {
		return nil, fmt.Errorf("spp: solana pk hash: %w", err)
	}
	return h, nil
}

// p256XHash commits the x-coordinate of a validated SEC1-compressed P256 key.
func p256XHash(compressed []byte) (*big.Int, error) {
	if len(compressed) != 33 {
		return nil, fmt.Errorf("expected 33-byte compressed P256 public key, got %d", len(compressed))
	}
	if compressed[0] != 0x02 && compressed[0] != 0x03 {
		return nil, fmt.Errorf("invalid compressed P256 public-key prefix 0x%02x", compressed[0])
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid compressed P256 public key")
	}
	var xBytes [32]byte
	x.FillBytes(xBytes[:])
	return HashBytes(xBytes[:])
}

// OwnerPkField is the parity-free commitment of a P256 x-coordinate.
func OwnerPkField(compressed []byte) (*big.Int, error) {
	xHash, err := p256XHash(compressed)
	if err != nil {
		return nil, fmt.Errorf("spp: P256 owner pk_field: %w", err)
	}
	return xHash, nil
}

// P256PkField is the viewing-key commitment:
// Poseidon(y_is_odd, HashBytes(x)).
func P256PkField(compressed []byte) (*big.Int, error) {
	xHash, err := p256XHash(compressed)
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
