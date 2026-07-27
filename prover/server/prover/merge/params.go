package merge

import (
	"math/big"

	"zolana/prover/prover/common"
)

// InputParams mirrors merge.Input. Only the free per-slot UTXO fields are
// carried; the shared owner/asset and the constant data/zone-program fields are
// reconstructed in-circuit. Every value is pre-computed client-side; the prover
// only assigns them onto circuit signals.
type InputParams struct {
	Domain       *big.Int
	Amount       *big.Int
	Blinding     *big.Int
	ZoneDataHash *big.Int

	StatePathElements []*big.Int // len StateTreeHeight
	StatePathIndex    *big.Int

	NullifierLowValue        *big.Int
	NullifierNextValue       *big.Int
	NullifierLowPathElements []*big.Int // len NullifierTreeHeight
	NullifierLowPathIndex    *big.Int

	UtxoTreeRoot      *big.Int
	NullifierTreeRoot *big.Int
	Nullifier         *big.Int
}

// OutputParams mirrors merge.Output: only the free leaf field plus the
// committed hash.
type OutputParams struct {
	ZoneDataHash *big.Int
	Hash         *big.Int
}

// MergeParameters is the flat, pre-computed witness for the 8-in/1-out merge
// circuit. The prover does no hashing: the client computes every field (utxo
// hashes, nullifiers, tree roots/proofs, the private-tx hash, the encryption,
// and the public-input hash) and sends them here.
type MergeParameters struct {
	// CircuitType selects the rail: MergeCircuitType (default) or
	// MergeZoneCircuitType (policy zone). It chooses which circuit the witness is
	// assigned onto.
	CircuitType common.CircuitType

	Inputs []InputParams
	Output OutputParams

	// Asset is the single asset shared by every real input and the merged output.
	Asset *big.Int

	// ZoneProgramID is the policy-zone merge circuit's top-level public
	// ZoneProgramID input (the zone program's pk_field). Every real input and the
	// output UTXO must carry this same value in their per-UTXO ZoneProgramID. It is
	// unused (and zero) on the default merge rail.
	ZoneProgramID *big.Int

	// Shared owner identity: the owner's pk_field and the nullifier
	// secret/commitment.
	OwnerPkHash         *big.Int
	UserNullifierPk     *big.Int
	UserNullifierSecret *big.Int

	// OutputZoneDataHash is the zone-data hash the calling zone program carries
	// in the merge_zone instruction/event. The zone circuit asserts it against
	// Output.ZoneDataHash and folds it into the public-input hash. Zero on the
	// default rail.
	OutputZoneDataHash *big.Int

	ExternalDataHash *big.Int
	PrivateTxHash    *big.Int
	AllowDummyInputs *big.Int

	PublicInputHash *big.Int
}
