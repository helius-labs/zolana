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

// OutputParams mirrors merge.Output: only the free leaf fields.
type OutputParams struct {
	Blinding     *big.Int
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

	// Shared owner identity: P256 signing pubkey coordinates and the nullifier
	// secret/commitment. OwnerPkHash is the owner's pk_field: 0 means P256-owned
	// (P256 path), a non-zero value is the Ed25519 owner's pk_field; it selects the rail.
	P256PubX            *big.Int
	P256PubY            *big.Int
	OwnerPkHash         *big.Int
	UserNullifierPk     *big.Int
	UserNullifierSecret *big.Int

	// Verifiable-encryption witnesses.
	TxViewingSk       *big.Int
	UserViewingPubkey []*big.Int // len 65, byte values of the uncompressed point
	TxViewingPkLo     *big.Int
	TxViewingPkHi     *big.Int
	CtHash            *big.Int
	UserViewingPkHash *big.Int

	ExternalDataHash *big.Int
	PrivateTxHash    *big.Int

	PublicInputHash *big.Int
}
