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
	"tree_slots",
	"output_tree_id",
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

// PublicInputNames returns the PublicInputHash preimage order. Variant-specific
// elements inserted after private_tx_hash (PreimageAfterPrivateTxHash) are not
// listed; they exist only on the P256 rail.
func PublicInputNames() []string {
	out := make([]string, len(publicInputNames))
	copy(out, publicInputNames[:])
	return out
}

type PublicInputs struct {
	Nullifiers       []*big.Int
	OutputUtxoHashes []*big.Int
	// TreeSlots are the InputTrees slots inputs spend from, unused slots all
	// zero at the end. They enter the preimage as one element, the tree slot
	// chain.
	TreeSlots []TreeSlot
	// OutputTreeID is the raw u16 id of the tree every output is appended to.
	OutputTreeID  *big.Int
	PrivateTxHash *big.Int
	// PreimageAfterPrivateTxHash holds the variant-specific elements inserted
	// right after PrivateTxHash: nil for the EdDSA rails, the P256 message hash
	// and the default P256 owner identity for the P256 rail.
	PreimageAfterPrivateTxHash []*big.Int
	ExternalDataHash           *big.Int
	PublicAssets               [NPublicSlots]*big.Int
	PublicAmounts              [NPublicSlots]*big.Int
	RingProgramID              *big.Int
	SignerPkHashes             []*big.Int
	AllowDummyInputs           *big.Int

	// BindOutputOwnerTags appends the output-owner chain for owner-signed rails.
	// Custom-ring values are masked to zero for anonymous outputs.
	BindOutputOwnerTags bool
	OutputOwnerPkHashes []*big.Int
}

// PublicInputHash mirrors Transaction.publicInputHash in the circuit.
func PublicInputHash(inputs PublicInputs) (*big.Int, error) {
	if len(inputs.TreeSlots) != InputTrees {
		return nil, fmt.Errorf(
			"spp: public input hash tree slot count: got %d want %d",
			len(inputs.TreeSlots), InputTrees,
		)
	}
	if inputs.OutputTreeID == nil {
		return nil, fmt.Errorf("spp: public input hash: output tree id is required")
	}
	nullifierChain, err := HashChain(inputs.Nullifiers)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier chain: %w", err)
	}
	outputChain, err := HashChain(inputs.OutputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash output chain: %w", err)
	}
	treeSlotChain, err := TreeSlotsHashChain(inputs.TreeSlots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash tree slot chain: %w", err)
	}
	fields := []*big.Int{
		nullifierChain,
		outputChain,
		treeSlotChain,
		inputs.OutputTreeID,
		inputs.PrivateTxHash,
	}
	fields = append(fields, inputs.PreimageAfterPrivateTxHash...)
	fields = append(fields, inputs.ExternalDataHash)
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
