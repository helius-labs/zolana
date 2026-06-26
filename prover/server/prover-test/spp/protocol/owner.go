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
	h, err := poseidon.Hash([]*big.Int{
		fieldFromU128BE(pubkey[16:]),
		fieldFromU128BE(pubkey[:16]),
	})
	if err != nil {
		return nil, fmt.Errorf("spp: solana pk hash: %w", err)
	}
	return h, nil
}

// p256XHash computes hash_field(x) = Poseidon(x_low128, x_high128) from a
// SEC1-compressed P256 key (validating the prefix). This is the parity-free owner
// pk_field; the viewing variant folds the y-parity on top.
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
	return poseidon.Hash([]*big.Int{
		fieldFromU128BE(xBytes[16:]),
		fieldFromU128BE(xBytes[:16]),
	})
}

// OwnerPkField is the rail-agnostic, parity-free owner pk_field: hash_field(x),
// matching the circuit OwnerPkFieldGadget and Rust PublicKey::owner_pk_field. The
// y-parity is carried in the encrypted data, not the owner identity.
func OwnerPkField(compressed []byte) (*big.Int, error) {
	xHash, err := p256XHash(compressed)
	if err != nil {
		return nil, fmt.Errorf("spp: P256 owner pk_field: %w", err)
	}
	return xHash, nil
}

// P256PkField is the VIEWING-key pk_field: Poseidon(y_is_odd, hash_field(x)),
// matching the circuit P256PkFieldGadget. The owner key uses OwnerPkField instead.
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

func fieldFromU128BE(bytes []byte) *big.Int {
	return new(big.Int).SetBytes(bytes)
}
