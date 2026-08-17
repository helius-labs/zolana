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

	OwnerPkHash *big.Int
	// NullifierSecret is the spend secret scalar. It derives the nullifier and
	// must be the discrete log of SpendPkX/SpendPkY, which the circuit checks.
	NullifierSecret *big.Int

	// Spend key and its signature over the transaction's private hash. Slots
	// that do not spend carry the neutral element (0, 1) and the signature
	// (R = (0, 1), S = 0) that verifies under it.
	SpendPkX  *big.Int
	SpendPkY  *big.Int
	SpendSigX *big.Int
	SpendSigY *big.Int
	SpendSigS *big.Int
}

// OutputParams mirrors txcircuit.Output. OwnerPkHash and the spend public key
// bind the output owner identity; only the default confidential rail publishes
// its owner tags. They are 0 for authority proofs. Outputs carry no signature:
// the recipient holds that key.
type OutputParams struct {
	Utxo        UtxoParams
	IsDummy     *big.Int
	Hash        *big.Int
	OwnerPkHash *big.Int
	SpendPkX    *big.Int
	SpendPkY    *big.Int
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

	PrivateTxHash *big.Int
	// PublicAssets/PublicAmounts are the uniform public movement slots, both of
	// length shared.NPublicSlots.
	PublicAssets                 []*big.Int
	PublicAmounts                []*big.Int
	ZoneProgramID                *big.Int
	SignerPkHashes               []*big.Int
	AllowDummyInputs             *big.Int
	PublishedOutputOwnerPkHashes []*big.Int

	// Variant selects the Solana-only instantiation: confidential default-zone,
	// confidential custom-zone, or zone-authority (anonymous, input owners
	// private, no signature).
	Variant Variant

	PublicInputHash *big.Int
}
