package transaction

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/parse"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

type ownerKey struct {
	keyHash     *big.Int
	nullifierPk *big.Int
}

type ownerFields struct {
	owner *big.Int
	ownerKey
}

func parseOwner(input ProofUtxoRequest, inputNullifierSecret *big.Int) (ownerFields, error) {
	if strings.TrimSpace(input.OwnerP256Pubkey) != "" {
		return ownerFields{}, fmt.Errorf("owner_p256_pubkey is unsupported")
	}
	if input.Owner != "" {
		owner, err := parse.Field(input.Owner)
		if err != nil {
			return ownerFields{}, fmt.Errorf("owner: %w", err)
		}
		if input.OwnerSolanaPubkey == "" {
			return ownerFields{owner: owner, ownerKey: ownerKey{keyHash: big.NewInt(0), nullifierPk: big.NewInt(0)}}, nil
		}
		key, err := ownerComponents(input, inputNullifierSecret)
		if err != nil {
			return ownerFields{}, err
		}
		// The circuit constrains owner == OwnerHash(key_hash, nullifier_pk), so an
		// explicit owner that disagrees with the supplied key components can only
		// build an unprovable witness. Reject it here with a clear error.
		expected, err := protocol.OwnerHash(key.keyHash, key.nullifierPk)
		if err != nil {
			return ownerFields{}, err
		}
		if owner.Cmp(expected) != 0 {
			return ownerFields{}, fmt.Errorf("owner: explicit owner does not match OwnerHash(key_hash, nullifier_pk)")
		}
		return ownerFields{owner: owner, ownerKey: key}, nil
	}
	key, err := ownerComponents(input, inputNullifierSecret)
	if err != nil {
		return ownerFields{}, err
	}
	owner, err := protocol.OwnerHash(key.keyHash, key.nullifierPk)
	if err != nil {
		return ownerFields{}, err
	}
	return ownerFields{owner: owner, ownerKey: key}, nil
}

func ownerComponents(input ProofUtxoRequest, inputNullifierSecret *big.Int) (ownerKey, error) {
	if strings.TrimSpace(input.OwnerP256Pubkey) != "" {
		return ownerKey{}, fmt.Errorf("owner_p256_pubkey is unsupported")
	}
	if strings.TrimSpace(input.OwnerSolanaPubkey) == "" {
		return ownerKey{}, fmt.Errorf("owner_solana_pubkey is required when owner components are needed")
	}
	pubkey, err := parse.Hex32(input.OwnerSolanaPubkey)
	if err != nil {
		return ownerKey{}, fmt.Errorf("owner_solana_pubkey: %w", err)
	}
	keyHash, err := protocol.SolanaPkField(pubkey)
	if err != nil {
		return ownerKey{}, fmt.Errorf("owner_solana_pubkey: %w", err)
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
	nullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		return ownerKey{}, err
	}
	return ownerKey{keyHash: keyHash, nullifierPk: nullifierPk}, nil
}
