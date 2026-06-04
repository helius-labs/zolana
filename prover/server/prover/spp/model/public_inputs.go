package model

import (
	"fmt"
	"math/big"
)

var logicalPublicInputNames = [...]string{
	"nullifiers",
	"output_utxo_hashes",
	"utxo_tree_roots",
	"nullifier_tree_roots",
	"private_tx_hash",
	"external_data_hash",
	"public_sol_amount",
	"public_spl_amount",
	"public_spl_asset_pubkey",
	"program_id_hashchain",
	"solana_pubkey_hash",
	"data_hash",
	"zone_data_hash",
	"solana_pk_hashes",
}

// LogicalPublicInputNames returns the PublicInputHash preimage order.
func LogicalPublicInputNames() []string {
	out := make([]string, len(logicalPublicInputNames))
	copy(out, logicalPublicInputNames[:])
	return out
}

type PublicInputs struct {
	Nullifiers           []*big.Int
	OutputUtxoHashes     []*big.Int
	UtxoTreeRoots        []*big.Int
	NullifierRoots       []*big.Int
	PrivateTxHash        *big.Int
	ExternalDataHash     *big.Int
	PublicSolAmount      *big.Int
	PublicSplAmount      *big.Int
	PublicSplAssetPubkey *big.Int
	ProgramIDHashchain   *big.Int
	SolanaPubkeyHash     *big.Int
	SolanaPkHashes       []*big.Int
	DataHash             *big.Int
	ZoneDataHash         *big.Int
}

func PublicInputHash(inputs PublicInputs) (*big.Int, error) {
	nullifierChain, err := HashChain(inputs.Nullifiers)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier chain: %w", err)
	}
	outputChain, err := HashChain(inputs.OutputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash output chain: %w", err)
	}
	utxoRootChain, err := HashChain(inputs.UtxoTreeRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash UTXO root chain: %w", err)
	}
	nullifierRootChain, err := HashChain(inputs.NullifierRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier root chain: %w", err)
	}
	solanaOwnerKeyHashChain, err := HashChain(inputs.SolanaPkHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash solana pk hash chain: %w", err)
	}
	return HashChain([]*big.Int{
		nullifierChain,
		outputChain,
		utxoRootChain,
		nullifierRootChain,
		inputs.PrivateTxHash,
		inputs.ExternalDataHash,
		inputs.PublicSolAmount,
		inputs.PublicSplAmount,
		inputs.PublicSplAssetPubkey,
		inputs.ProgramIDHashchain,
		inputs.SolanaPubkeyHash,
		inputs.DataHash,
		inputs.ZoneDataHash,
		solanaOwnerKeyHashChain,
	})
}
