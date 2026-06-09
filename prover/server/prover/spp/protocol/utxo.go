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
// Every real (non-dummy) UTXO must carry this domain.
const UtxoDomain = 1

// Utxo fields are ordered exactly as the Poseidon preimage.
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

func (u Utxo) Fields() []*big.Int {
	return []*big.Int{
		u.Domain,
		u.Owner,
		u.AssetID,
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
