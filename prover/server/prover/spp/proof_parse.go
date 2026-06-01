package spp

import (
	"fmt"
	"math/big"
	"strings"
)

func parseProofInput(input ProofInputRequest) (proofInput, error) {
	// An input must carry owner key material: the spend is authorized by
	// recomputing the owner hash from it. An owner-only UTXO (no pubkey) is
	// valid for outputs but cannot be spent, so reject it here rather than let
	// it fail later as an opaque owner-hash mismatch.
	if strings.TrimSpace(input.Utxo.OwnerSolanaPubkey) == "" && strings.TrimSpace(input.Utxo.OwnerP256Pubkey) == "" {
		return proofInput{}, fmt.Errorf("input UTXO requires owner_solana_pubkey or owner_p256_pubkey to authorize the spend")
	}
	nullifierSecret, err := parseField(input.NullifierSecret)
	if err != nil {
		return proofInput{}, fmt.Errorf("nullifier_secret: %w", err)
	}
	parsed, err := parseProofUtxo(input.Utxo, nullifierSecret)
	if err != nil {
		return proofInput{}, err
	}
	return proofInput{
		utxo:            parsed.utxo,
		leafIndex:       input.LeafIndex,
		nullifierSecret: nullifierSecret,
		ownerKeyHash:    parsed.ownerKeyHash,
		nullifierPk:     parsed.nullifierPk,
		isP256:          parsed.isP256,
	}, nil
}

// parsedUtxo holds a ProofUtxoRequest decoded into its circuit fields plus the
// owner material derived alongside it. response is the copy echoed back in the
// transaction response: field elements are canonicalized to 64-char hex, while
// owner pubkeys are only stripped of any "0x" prefix (they are not field
// elements, so they are passed through, not canonicalized).
type parsedUtxo struct {
	utxo         Utxo
	response     ProofUtxoRequest
	ownerKeyHash *big.Int
	nullifierPk  *big.Int
	isP256       bool
}

func parseProofUtxo(input ProofUtxoRequest, inputNullifierSecret *big.Int) (parsedUtxo, error) {
	domain, err := parseField(input.Domain)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("domain: %w", err)
	}
	own, err := parseOwner(input, inputNullifierSecret)
	if err != nil {
		return parsedUtxo{}, err
	}
	asset, err := parseField(input.Asset)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("asset: %w", err)
	}
	assetAmount, err := parseField(input.AssetAmount)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("asset_amount: %w", err)
	}
	blinding, err := parseField(input.Blinding)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("blinding: %w", err)
	}
	dataHash, err := optionalField(input.DataHash)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("data_hash: %w", err)
	}
	policyData, err := optionalField(input.PolicyData)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("policy_data: %w", err)
	}
	policyProgramID, err := optionalField(input.PolicyProgramID)
	if err != nil {
		return parsedUtxo{}, fmt.Errorf("policy_program_id: %w", err)
	}
	utxo := Utxo{
		Domain:          domain,
		Owner:           own.owner,
		Asset:           asset,
		AssetAmount:     assetAmount,
		Blinding:        blinding,
		DataHash:        dataHash,
		PolicyData:      policyData,
		PolicyProgramID: policyProgramID,
	}
	response := ProofUtxoRequest{
		Domain:            proofFieldHex(domain),
		Owner:             proofFieldHex(own.owner),
		OwnerSolanaPubkey: strings.TrimPrefix(input.OwnerSolanaPubkey, "0x"),
		OwnerP256Pubkey:   strings.TrimPrefix(input.OwnerP256Pubkey, "0x"),
		Asset:             proofFieldHex(asset),
		AssetAmount:       proofFieldHex(assetAmount),
		Blinding:          proofFieldHex(blinding),
		DataHash:          proofFieldHex(dataHash),
		PolicyData:        proofFieldHex(policyData),
		PolicyProgramID:   proofFieldHex(policyProgramID),
	}
	return parsedUtxo{
		utxo:         utxo,
		response:     response,
		ownerKeyHash: own.keyHash,
		nullifierPk:  own.nullifierPk,
		isP256:       own.isP256,
	}, nil
}

// ownerKey is the key material derived from a UTXO owner's Solana or P256 pubkey.
type ownerKey struct {
	keyHash     *big.Int
	nullifierPk *big.Int
	isP256      bool
}

// ownerFields is a fully resolved UTXO owner: the owner hash plus its key material.
type ownerFields struct {
	owner *big.Int
	ownerKey
}

func parseOwner(input ProofUtxoRequest, inputNullifierSecret *big.Int) (ownerFields, error) {
	if input.Owner != "" {
		owner, err := parseField(input.Owner)
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
		// Both an explicit owner and key components were supplied: they must
		// agree, otherwise the circuit's owner-hash binding would just fail with
		// an opaque error. Reject the inconsistency here with a clear message.
		derived, err := OwnerHash(key.keyHash, key.nullifierPk)
		if err != nil {
			return ownerFields{}, err
		}
		if derived.Cmp(owner) != 0 {
			return ownerFields{}, fmt.Errorf("owner %s does not match the hash of the supplied owner components", input.Owner)
		}
		return ownerFields{owner: owner, ownerKey: key}, nil
	}
	key, err := ownerComponents(input, inputNullifierSecret)
	if err != nil {
		return ownerFields{}, err
	}
	owner, err := OwnerHash(key.keyHash, key.nullifierPk)
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
		pubkey, err = parseHex32(input.OwnerSolanaPubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_solana_pubkey: %w", err)
		}
		keyHash, err = SolanaPkHash(pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_solana_pubkey: %w", err)
		}
	} else {
		var pubkey []byte
		pubkey, err = parseHexBytes(input.OwnerP256Pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_p256_pubkey: %w", err)
		}
		keyHash, err = P256OwnerKeyHash(pubkey)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_p256_pubkey: %w", err)
		}
		isP256 = true
	}
	nullifierSecret := inputNullifierSecret
	if nullifierSecret == nil {
		if input.OwnerNullifierSecret == "" {
			return ownerKey{}, fmt.Errorf("owner_nullifier_secret is required to derive owner key material from the supplied pubkey")
		}
		nullifierSecret, err = parseField(input.OwnerNullifierSecret)
		if err != nil {
			return ownerKey{}, fmt.Errorf("owner_nullifier_secret: %w", err)
		}
	}
	nullifierPk, err := NullifierPk(nullifierSecret)
	if err != nil {
		return ownerKey{}, err
	}
	return ownerKey{keyHash: keyHash, nullifierPk: nullifierPk, isP256: isP256}, nil
}
