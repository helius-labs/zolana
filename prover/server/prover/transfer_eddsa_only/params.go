package transfereddsaonly

import (
	"math/big"

	"zolana/prover/prover/common"
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
	RingDataHash  *big.Int
	RingProgramID *big.Int
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

	// TreeSlot is the private index into TransferParameters.TreeSlots of the
	// tree this input is spent from. It selects the slot's id and both roots as
	// a unit, so a UTXO cannot be hashed under one tree and proven against
	// another tree's roots.
	TreeSlot  *big.Int
	Nullifier *big.Int

	OwnerPkHash     *big.Int
	NullifierSecret *big.Int
}

// OutputParams mirrors txcircuit.Output. OwnerPkHash and NullifierPk bind the
// output owner identity; only the default confidential rail publishes its owner
// tags. They are 0 for authority proofs.
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
	// TreeSlots are the shared.InputTrees public tree slots inputs may be spent
	// from; unused slots are all zero. Each input names its own slot privately.
	TreeSlots []common.TreeSlotParams
	// OutputTreeID is the raw u16 id of the tree every output is appended to.
	OutputTreeID *big.Int

	ExternalDataHash *big.Int

	PrivateTxHash *big.Int
	// TxSecret is the transaction's single private random value. The circuit
	// derives the output blinding seed, every output blinding, and the private
	// tx blinding from it and the first nullifier, so none of those are sent.
	// A caller-supplied output blinding must equal the derived one or the proof
	// fails.
	TxSecret *big.Int
	// PublicAssets/PublicAmounts are the uniform public movement slots, both of
	// length shared.NPublicSlots.
	PublicAssets                 []*big.Int
	PublicAmounts                []*big.Int
	RingProgramID                *big.Int
	SignerPkHashes               []*big.Int
	AllowDummyInputs             *big.Int
	PublishedOutputOwnerPkHashes []*big.Int

	// Variant selects the Solana-only instantiation: confidential default-ring,
	// confidential custom-ring, or ring-authority (anonymous, input owners
	// private, no signature).
	Variant Variant

	PublicInputHash *big.Int
}
