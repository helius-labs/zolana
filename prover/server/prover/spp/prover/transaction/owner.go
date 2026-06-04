package transaction

import (
	"fmt"
	"math/big"
	"strings"

	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"
)

type ownerKey struct {
	keyHash     *big.Int
	nullifierPk *big.Int
	isP256      bool
}

type ownerFields struct {
	owner *big.Int
	ownerKey
}

func parseOwner(input ProofUtxoRequest, inputNullifierSecret *big.Int) (ownerFields, error) {
	if input.Owner != "" {
		owner, err := parse.Field(input.Owner)
		if err != nil {
			return ownerFields{}, fmt.Errorf("owner: %w", err)
		}
		if input.OwnerSolanaPubkey == "" && input.OwnerP256Pubkey == "" {
			return ownerFields{owner: owner, ownerKey: ownerKey{keyHash: big.NewInt(0), nullifierPk: big.NewInt(0)}}, nil
		}
		key, err := ownerComponents(input, inputNullifierSecret)
		if err != nil {
			return ownerFields{}, err
		}
		return ownerFields{owner: owner, ownerKey: key}, nil
	}
	key, err := ownerComponents(input, inputNullifierSecret)
	if err != nil {
		return ownerFields{}, err
	}
	owner, err := model.OwnerHash(key.keyHash, key.nullifierPk)
	if err != nil {
		return ownerFields{}, err
	}
	return ownerFields{owner: owner, ownerKey: key}, nil
}

func ownerComponents(input ProofUtxoRequest, inputNullifierSecret *big.Int) (ownerKey, error) {
	hasSolana := strings.TrimSpace(input.OwnerSolanaPubkey) != ""
	hasP256 := strings.TrimSpace(input.OwnerP256Pubkey) != ""
	if hasSolana == hasP256 {
		return ownerKey{}, fmt.Errorf("exactly one owner_solana_pubkey or owner_p256_pubkey is required when owner components are needed")
	}

	var keyHash *big.Int
	var err error
	isP256 := false
	if hasSolana {
		var pubkey [32]byte
		pubkey, err = parse.Hex32(input.OwnerSolanaPubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_solana_pubkey: %w", err)
		}
		keyHash, err = model.SolanaPkHash(pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_solana_pubkey: %w", err)
		}
	} else {
		var pubkey []byte
		pubkey, err = parse.HexBytes(input.OwnerP256Pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_p256_pubkey: %w", err)
		}
		keyHash, err = model.P256OwnerKeyHash(pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_p256_pubkey: %w", err)
		}
		isP256 = true
	}

	nullifierSecret := inputNullifierSecret
	if nullifierSecret == nil {
		if input.OwnerNullifierSecret == "" {
			return ownerKey{}, fmt.Errorf("owner_nullifier_secret is required when owner is omitted")
		}
		nullifierSecret, err = parse.Field(input.OwnerNullifierSecret)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_nullifier_secret: %w", err)
		}
	}
	nullifierPk, err := model.NullifierPk(nullifierSecret)
	if err != nil {
		return ownerKey{}, err
	}
	return ownerKey{keyHash: keyHash, nullifierPk: nullifierPk, isP256: isP256}, nil
}
