package protocol

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
)

// solAssetValue is the UTXO asset field for native SOL: the default (all-zero)
// address encoded like any Address in a UTXO commitment, Poseidon(low_128,
// high_128) == Poseidon(0, 0). Spec: SOL is Address::default(), and the SPL
// asset uses the same SolanaPkHash encoding (on-chain public_spl_asset).
var solAssetValue = mustSolAsset()

func mustSolAsset() *big.Int {
	asset, err := SolanaPkHash([32]byte{})
	if err != nil {
		panic(err)
	}
	return asset
}

// SolAsset returns the native-SOL asset field used in UTXO commitments and the
// balance check.
func SolAsset() *big.Int {
	return new(big.Int).Set(solAssetValue)
}

// UtxoDomain is the constant domain separator for UTXO Poseidon commitments
// (spec: "Constant separating UTXOs from other Poseidon-hashed records").
// Every real (non-dummy) UTXO must carry this domain. Bumped to 2 when the
// commitment preimage changed to the owner-hiding nested form, so old (flat)
// and new (nested) UTXO hashes can never be confused.
const UtxoDomain = 2

type Utxo struct {
	Domain        *big.Int
	Owner         *big.Int
	AssetID       *big.Int
	AssetAmount   *big.Int
	Blinding      *big.Int
	DataHash      *big.Int
	ZoneDataHash  *big.Int
	ZoneProgramID *big.Int
}

// OwnerUtxoHash nests the owner and blinding into a single field,
// owner_utxo_hash = Poseidon(owner, blinding). The UTXO commitment carries this
// instead of owner+blinding directly, so a proofless shield can commit to a
// recipient without revealing the owner. The spend circuit re-derives it from
// the (private) owner and blinding witnesses.
func OwnerUtxoHash(owner, blinding *big.Int) (*big.Int, error) {
	h, err := poseidon.HashWithT(3, []*big.Int{owner, blinding})
	if err != nil {
		return nil, fmt.Errorf("spp: owner utxo hash: %w", err)
	}
	return h, nil
}

func UtxoHash(u Utxo) (*big.Int, error) {
	ownerUtxoHash, err := OwnerUtxoHash(u.Owner, u.Blinding)
	if err != nil {
		return nil, err
	}
	h, err := poseidon.HashWithT(8, []*big.Int{
		u.Domain,
		u.AssetID,
		u.AssetAmount,
		u.DataHash,
		u.ZoneDataHash,
		u.ZoneProgramID,
		ownerUtxoHash,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: utxo hash: %w", err)
	}
	return h, nil
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
