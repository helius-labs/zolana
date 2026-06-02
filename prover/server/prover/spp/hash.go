package spp

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
)

// Utxo is the field-element view of a UTXO. Field order matters: it is the
// Poseidon hash preimage.
type Utxo struct {
	Domain        *big.Int
	Owner         *big.Int
	Asset         *big.Int
	AssetAmount   *big.Int
	Blinding      *big.Int
	DataHash      *big.Int
	ZoneDataHash  *big.Int
	ZoneProgramID *big.Int
}

func (u Utxo) Fields() []*big.Int {
	return []*big.Int{
		u.Domain,
		u.Owner,
		u.Asset,
		u.AssetAmount,
		u.Blinding,
		u.DataHash,
		u.ZoneDataHash,
		u.ZoneProgramID,
	}
}

func UtxoHash(u Utxo) (*big.Int, error) {
	h, err := poseidon.HashWithT(9, u.Fields())
	if err != nil {
		return nil, fmt.Errorf("spp: utxo hash: %w", err)
	}
	return h, nil
}

func NullifierPk(nullifierSecret *big.Int) (*big.Int, error) {
	h, err := poseidon.HashWithT(2, []*big.Int{nullifierSecret})
	if err != nil {
		return nil, fmt.Errorf("spp: nullifier pk: %w", err)
	}
	return h, nil
}

func OwnerHash(ownerKeyHash, nullifierPk *big.Int) (*big.Int, error) {
	h, err := poseidon.HashWithT(3, []*big.Int{ownerKeyHash, nullifierPk})
	if err != nil {
		return nil, fmt.Errorf("spp: owner hash: %w", err)
	}
	return h, nil
}

func SolanaPkHash(pubkey [32]byte) (*big.Int, error) {
	h, err := poseidon.HashWithT(3, []*big.Int{
		fieldFromU128BE(pubkey[16:]),
		fieldFromU128BE(pubkey[:16]),
	})
	if err != nil {
		return nil, fmt.Errorf("spp: solana pk hash: %w", err)
	}
	return h, nil
}

func P256OwnerKeyHash(compressed []byte) (*big.Int, error) {
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
	xHash, err := poseidon.HashWithT(3, []*big.Int{
		fieldFromU128BE(xBytes[16:]),
		fieldFromU128BE(xBytes[:16]),
	})
	if err != nil {
		return nil, fmt.Errorf("spp: P256 x hash: %w", err)
	}
	h, err := poseidon.HashWithT(3, []*big.Int{
		new(big.Int).SetUint64(uint64(compressed[0] & 1)),
		xHash,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: P256 owner key hash: %w", err)
	}
	return h, nil
}

func fieldFromU128BE(bytes []byte) *big.Int {
	return new(big.Int).SetBytes(bytes)
}

func NullifierHash(utxoHash, blinding, nullifierSecret *big.Int) (*big.Int, error) {
	h, err := poseidon.HashWithT(4, []*big.Int{utxoHash, blinding, nullifierSecret})
	if err != nil {
		return nil, fmt.Errorf("spp: nullifier hash: %w", err)
	}
	return h, nil
}

func NullifierFromSecret(utxo Utxo, nullifierSecret *big.Int) (*big.Int, error) {
	utxoHash, err := UtxoHash(utxo)
	if err != nil {
		return nil, err
	}
	return NullifierHash(utxoHash, utxo.Blinding, nullifierSecret)
}

func HashToFieldSize(data ...[]byte) *big.Int {
	hasher := sha256.New()
	for _, item := range data {
		hasher.Write(item)
	}
	sum := hasher.Sum(nil)
	sum[0] = 0
	return new(big.Int).SetBytes(sum)
}

// HashChain is the canonical SPP hash chain: a left fold over Poseidon.
//
//	h = inputs[0]
//	for i = 1; i < len(inputs); i++:
//	    h = Poseidon(h, inputs[i])
//
// Empty chains return zero. Single-element chains return that element.
func HashChain(inputs []*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return new(big.Int), nil
	}
	for i, input := range inputs {
		if err := validateFieldElement(fmt.Sprintf("input[%d]", i), input); err != nil {
			return nil, fmt.Errorf("spp: hash chain: %w", err)
		}
	}

	h := new(big.Int).Set(inputs[0])
	for i := 1; i < len(inputs); i++ {
		next, err := poseidon.HashWithT(3, []*big.Int{h, inputs[i]})
		if err != nil {
			return nil, fmt.Errorf("spp: hash chain step %d: %w", i, err)
		}
		h = next
	}
	return h, nil
}

func PrivateTxHash(
	inputUtxoHashes []*big.Int,
	outputUtxoHashes []*big.Int,
	externalDataHash *big.Int,
) (*big.Int, error) {
	inputChain, err := HashChain(inputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash input chain: %w", err)
	}
	outputChain, err := HashChain(outputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash output chain: %w", err)
	}

	h, err := poseidon.HashWithT(4, []*big.Int{
		inputChain,
		outputChain,
		externalDataHash,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash: %w", err)
	}
	return h, nil
}

func validateFieldElement(name string, value *big.Int) error {
	if value == nil {
		return fmt.Errorf("%s is nil", name)
	}
	if value.Sign() < 0 {
		return fmt.Errorf("%s is negative", name)
	}
	if value.Cmp(poseidon.Modulus) >= 0 {
		return fmt.Errorf("%s exceeds BN254 field modulus", name)
	}
	return nil
}
