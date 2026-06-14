package protocol

import (
	"fmt"
	"math/big"
)

var publicInputNames = [...]string{
	"nullifiers",
	"output_utxo_hashes",
	"utxo_tree_roots",
	"nullifier_tree_roots",
	"private_tx_hash",
	"p256_message_hash",
	"external_data_hash",
	"public_sol_amount",
	"public_spl_amount",
	"public_spl_asset_pubkey",
	"program_id_hashchain",
	"payer_pubkey_hash",
	"data_hash",
	"zone_data_hash",
	"solana_owner_pk_hashes",
}

// PublicInputNames returns the PublicInputHash preimage order.
func PublicInputNames() []string {
	out := make([]string, len(publicInputNames))
	copy(out, publicInputNames[:])
	return out
}

type PublicInputs struct {
	Nullifiers           []*big.Int
	OutputUtxoHashes     []*big.Int
	UtxoTreeRoots        []*big.Int
	NullifierTreeRoots   []*big.Int
	PrivateTxHash        *big.Int
	P256MessageHash      *big.Int
	ExternalDataHash     *big.Int
	PublicSolAmount      *big.Int
	PublicSplAmount      *big.Int
	PublicSplAssetPubkey *big.Int
	ProgramIDHashchain   *big.Int
	PayerPubkeyHash      *big.Int
	SolanaOwnerPkHashes  []*big.Int
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
	nullifierTreeRootChain, err := HashChain(inputs.NullifierTreeRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier root chain: %w", err)
	}
	solanaOwnerChain, err := HashChain(inputs.SolanaOwnerPkHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash solana owner chain: %w", err)
	}
	return HashChain([]*big.Int{
		nullifierChain,
		outputChain,
		utxoRootChain,
		nullifierTreeRootChain,
		inputs.PrivateTxHash,
		inputs.P256MessageHash,
		inputs.ExternalDataHash,
		inputs.PublicSolAmount,
		inputs.PublicSplAmount,
		inputs.PublicSplAssetPubkey,
		inputs.ProgramIDHashchain,
		inputs.PayerPubkeyHash,
		inputs.DataHash,
		inputs.ZoneDataHash,
		solanaOwnerChain,
	})
}
