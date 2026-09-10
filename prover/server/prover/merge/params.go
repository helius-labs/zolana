package merge

import (
	"math/big"

	"zolana/prover/prover/common"
)

// InputParams mirrors merge.Input. Only the free per-slot UTXO fields are
// carried; the shared owner/asset and the constant data/ring-program fields are
// reconstructed in-circuit. Every value is pre-computed client-side; the prover
// only assigns them onto circuit signals.
type InputParams struct {
	Domain       *big.Int
	Amount       *big.Int
	Blinding     *big.Int
	RingDataHash *big.Int

	StatePathElements []*big.Int // len StateTreeHeight
	StatePathIndex    *big.Int

	NullifierLowValue        *big.Int
	NullifierNextValue       *big.Int
	NullifierLowPathElements []*big.Int // len NullifierTreeHeight
	NullifierLowPathIndex    *big.Int

	// TreeSlot indexes MergeParameters.TreeSlots and stays private: it selects
	// the tree id this input's UTXO was hashed under together with the UTXO and
	// nullifier roots it is proven against, so the three cannot be mixed across
	// trees.
	TreeSlot  *big.Int
	Nullifier *big.Int
}

// OutputParams mirrors merge.Output: only the free leaf field plus the
// committed hash.
type OutputParams struct {
	RingDataHash *big.Int
	Hash         *big.Int
}

// MergeParameters is the flat, pre-computed witness for the 8-in/1-out merge
// circuit. The prover does no hashing: the client computes every field (utxo
// hashes, nullifiers, tree roots/proofs, the private-tx hash, the encryption,
// and the public-input hash) and sends them here.
type MergeParameters struct {
	// CircuitType selects the rail: MergeCircuitType (default) or
	// MergeRingCircuitType (policy ring). It chooses which circuit the witness is
	// assigned onto.
	CircuitType common.CircuitType

	Inputs []InputParams
	Output OutputParams

	// TreeSlots are the InputTrees public tree slots inputs may be spent from,
	// each an id with the UTXO and nullifier roots SPP resolved for it. Unused
	// slots are all zero and no input may select one.
	TreeSlots []common.TreeSlotParams

	// OutputTreeID is the raw u16 id of the tree the merged output is inserted
	// into; the output UTXO hash commits to it, so it need not match any input
	// slot's tree.
	OutputTreeID *big.Int

	// Asset is the single asset shared by every real input and the merged output.
	Asset *big.Int

	// RingProgramID is the policy-ring merge circuit's top-level public
	// RingProgramID input (the ring program's pk_field). Every real input and the
	// output UTXO must carry this same value in their per-UTXO RingProgramID. It is
	// unused (and zero) on the default merge rail.
	RingProgramID *big.Int

	// Shared owner identity: the owner's pk_field and the nullifier
	// secret/commitment. UserNullifierSecret also seeds the private tx blinding
	// and the merged output's blinding, both derived in-circuit, so no wire
	// field carries either.
	OwnerPkHash         *big.Int
	UserNullifierPk     *big.Int
	UserNullifierSecret *big.Int

	// OutputRingDataHash is the ring-data hash the calling ring program carries
	// in the merge_ring instruction/event. The ring circuit asserts it against
	// Output.RingDataHash and folds it into the public-input hash. Zero on the
	// default rail.
	OutputRingDataHash *big.Int

	ExternalDataHash *big.Int
	PrivateTxHash    *big.Int
	AllowDummyInputs *big.Int

	PublicInputHash *big.Int
}
