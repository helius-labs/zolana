package protocol

import (
	"fmt"
	"math/big"
)

// NPublicSlots mirrors the circuit constant of the same name.
const NPublicSlots = 3

var publicInputNames = [...]string{
	"nullifiers",
	"output_utxo_hashes",
	"utxo_tree_roots",
	"nullifier_tree_roots",
	"private_tx_hash",
	"external_data_hash",
	"public_asset_0",
	"public_amount_0",
	"public_asset_1",
	"public_amount_1",
	"public_asset_2",
	"public_amount_2",
	"ring_program_id",
	"signer_pk_hashes",
	"allow_dummy_inputs",
	"output_owner_pk_hashes",
}

// PublicInputNames returns the PublicInputHash preimage order.
func PublicInputNames() []string {
	out := make([]string, len(publicInputNames))
	copy(out, publicInputNames[:])
	return out
}

type PublicInputs struct {
	Nullifiers         []*big.Int
	OutputUtxoHashes   []*big.Int
	UtxoTreeRoots      []*big.Int
	NullifierTreeRoots []*big.Int
	PrivateTxHash      *big.Int
	ExternalDataHash   *big.Int
	PublicAssets       [NPublicSlots]*big.Int
	PublicAmounts      [NPublicSlots]*big.Int
	RingProgramID      *big.Int
	SignerPkHashes     []*big.Int
	AllowDummyInputs   *big.Int

	// BindOutputOwnerTags appends the output-owner chain for owner-signed rails.
	// Custom-ring values are masked to zero for anonymous outputs.
	BindOutputOwnerTags bool
	OutputOwnerPkHashes []*big.Int
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
	fields := []*big.Int{
		nullifierChain,
		outputChain,
		utxoRootChain,
		nullifierTreeRootChain,
		inputs.PrivateTxHash,
		inputs.ExternalDataHash,
	}
	for i := 0; i < NPublicSlots; i++ {
		fields = append(fields, inputs.PublicAssets[i], inputs.PublicAmounts[i])
	}
	// Everything from here on is variant-dependent, so the preimage keeps the
	// owner tags each variant publishes at the end.
	solanaOwnerChain, err := RightHashChain(inputs.SignerPkHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash solana owner chain: %w", err)
	}
	fields = append(fields,
		inputs.RingProgramID,
		solanaOwnerChain,
		inputs.AllowDummyInputs,
	)
	if inputs.BindOutputOwnerTags {
		outputOwnerChain, err := HashChain(inputs.OutputOwnerPkHashes)
		if err != nil {
			return nil, fmt.Errorf("spp: public input hash output owner chain: %w", err)
		}
		fields = append(fields, outputOwnerChain)
	}
	return HashChain(fields)
}
