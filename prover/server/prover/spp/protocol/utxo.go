package protocol

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
)

// SolAssetID is the protocol asset id for native SOL.
const SolAssetID = 1

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
