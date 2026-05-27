package spp

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"

	"golang.org/x/crypto/sha3"
)

// Utxo is the field-element view of the SPP UTXO hash preimage.
//
// Field order matches ../docs/spec.md:
//
//	domain, owner, asset_id, asset_amount, blinding,
//	data_hash, policy_data, policy_program_id
type Utxo struct {
	Domain          *big.Int
	Owner           *big.Int
	AssetID         *big.Int
	AssetAmount     *big.Int
	Blinding        *big.Int
	DataHash        *big.Int
	PolicyData      *big.Int
	PolicyProgramID *big.Int
}

func (u Utxo) Fields() []*big.Int {
	return []*big.Int{
		u.Domain,
		u.Owner,
		u.AssetID,
		u.AssetAmount,
		u.Blinding,
		u.DataHash,
		u.PolicyData,
		u.PolicyProgramID,
	}
}

func UtxoHash(u Utxo) (*big.Int, error) {
	h, err := poseidon.HashWithT(9, u.Fields())
	if err != nil {
		return nil, fmt.Errorf("spp: utxo hash: %w", err)
	}
	return h, nil
}

func PreNullifier(blinding, nullifierSecret *big.Int) (*big.Int, error) {
	// TODO(v2): commit note-scoped nullifier material in the UTXO hash so the
	// wallet secret is constrained by the note commitment instead of only by
	// this per-note pre-nullifier handoff.
	h, err := poseidon.HashWithT(3, []*big.Int{blinding, nullifierSecret})
	if err != nil {
		return nil, fmt.Errorf("spp: pre-nullifier: %w", err)
	}
	return h, nil
}

func NullifierHash(utxoHash, preNullifier *big.Int) (*big.Int, error) {
	h, err := poseidon.HashWithT(3, []*big.Int{utxoHash, preNullifier})
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
	preNullifier, err := PreNullifier(utxo.Blinding, nullifierSecret)
	if err != nil {
		return nil, err
	}
	return NullifierHash(utxoHash, preNullifier)
}

func HashToFieldSize(data ...[]byte) *big.Int {
	hasher := sha3.NewLegacyKeccak256()
	for _, item := range data {
		hasher.Write(item)
	}
	hasher.Write([]byte{255})
	sum := hasher.Sum(nil)
	sum[0] = 0
	return new(big.Int).SetBytes(sum)
}

// HashChain is the canonical SPP v0 Poseidon2 right-fold:
//
//	h = inputs[N-1]
//	for i = N-2; i >= 0; i--:
//	    h = Poseidon(inputs[i], h)
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

	h := new(big.Int).Set(inputs[len(inputs)-1])
	for i := len(inputs) - 2; i >= 0; i-- {
		next, err := poseidon.HashWithT(3, []*big.Int{inputs[i], h})
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
	expiryUnixTs *big.Int,
) (*big.Int, error) {
	inputChain, err := HashChain(inputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash input chain: %w", err)
	}
	outputChain, err := HashChain(outputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash output chain: %w", err)
	}

	h, err := poseidon.HashWithT(5, []*big.Int{
		inputChain,
		outputChain,
		externalDataHash,
		expiryUnixTs,
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
