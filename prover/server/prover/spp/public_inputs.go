package spp

import (
	"fmt"
	"math/big"
)

// LogicalPublicInputNames is the SPP public-input set. Expiry and relayer fee
// are not public inputs but are bound through external_data_hash (expiry also
// through private_tx_hash). public_amount_mode is not hashed at all: it only
// picks the sign of public_sol_amount/public_spl_amount, which are bound via
// PublicInputHash. The sign convention is fixed on-chain by the instruction
// discriminator (bound in external_data_hash), so a mode that disagrees with it
// yields signed amounts that fail verification.
var LogicalPublicInputNames = []string{
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
	"solana_pk_hashes",
}

// PublicInputs is the off-circuit copy of the values folded into
// PublicInputHash. Field order matches LogicalPublicInputNames and the in-circuit
// (*Circuit).publicInputHash, so the on-chain verifier rebuilds the same BN254
// field element.
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
	ProgramIDHashChain   *big.Int
	SolanaPubkeyHash     *big.Int
	SolanaPkHashes       []*big.Int
}

// PublicInputHash folds the logical public inputs into one field element. The
// variable-length groups (nullifiers, output hashes, tree roots, solana pk
// hashes) are each hashed into one value first, then folded with the scalar
// inputs in the same order as (*Circuit).publicInputHash.
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
		inputs.ProgramIDHashChain,
		inputs.SolanaPubkeyHash,
		solanaOwnerKeyHashChain,
	})
}
