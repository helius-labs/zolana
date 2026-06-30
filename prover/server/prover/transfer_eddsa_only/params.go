package transfereddsaonly

import (
	"math/big"
)

// UtxoParams mirrors txcircuit.UtxoCircuitFields as already-computed field
// elements supplied by the client.
type UtxoParams struct {
	Domain        *big.Int
	Owner         *big.Int
	Asset         *big.Int
	Amount        *big.Int
	Blinding      *big.Int
	DataHash      *big.Int
	ZoneDataHash  *big.Int
	ZoneProgramID *big.Int
}

// InputParams mirrors txcircuit.Input. Every value is pre-computed client-side;
// the prover only assigns them onto circuit signals.
type InputParams struct {
	Utxo              UtxoParams
	IsDummy           *big.Int
	StatePathElements []*big.Int // len StateTreeHeight
	StatePathIndex    *big.Int

	NullifierLowValue        *big.Int
	NullifierNextValue       *big.Int
	NullifierLowPathElements []*big.Int // len NullifierTreeHeight
	NullifierLowPathIndex    *big.Int

	UtxoTreeRoot      *big.Int
	NullifierTreeRoot *big.Int
	Nullifier         *big.Int

	OwnerPkHash     *big.Int
	NullifierSecret *big.Int
}

// OutputParams mirrors txcircuit.Output. OwnerPkHash and NullifierPk are used by
// the confidential variant; 0 otherwise.
type OutputParams struct {
	Utxo        UtxoParams
	IsDummy     *big.Int
	Hash        *big.Int
	OwnerPkHash *big.Int
	NullifierPk *big.Int
}

// TransferParameters is the flat, pre-computed witness for the Solana-only
// spp_transaction circuit. This rail has no P256 gadget: there is no P256
// pubkey/signature/message-hash, and every real input must be Solana-owned. The
// prover does no hashing — the client computes every field.
type TransferParameters struct {
	NInputs  uint32
	NOutputs uint32

	Inputs  []InputParams
	Outputs []OutputParams

	ExternalDataHash *big.Int

	PrivateTxHash        *big.Int
	PublicSolAmount      *big.Int
	PublicSplAmount      *big.Int
	PublicSplAssetPubkey *big.Int
	ZoneProgramID        *big.Int
	PayerPubkeyHash      *big.Int

	// Variant selects the Solana-only instantiation: confidential (non-zone, binds
	// output owner tags), anonymous zone, or zone-authority (anonymous, input
	// owners private, no signature).
	Variant Variant

	PublicInputHash *big.Int
}
