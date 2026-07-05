package squadszone

import "math/big"

// UtxoParams mirrors zoneutils.Utxo as already-computed field elements supplied
// by the client.
type UtxoParams struct {
	OwnerHash       *big.Int
	Asset           *big.Int
	Amount          *big.Int
	Blinding        *big.Int
	ProgramDataHash *big.Int
	ZoneDataHash    *big.Int
	ZoneProgramID   *big.Int
}

// SenderParams mirrors the squads ViewingKeyAccount on the sender side: the
// public account fields plus the private secrets the prover witnesses.
// SharedViewingSecretKey is a P-256 scalar (Fr).
type SenderParams struct {
	Owner                            *big.Int
	SharedViewingSecretKeyCommitment *big.Int
	NullifierPubkey                  *big.Int
	NullifierSecret                  *big.Int
	SharedViewingSecretKey           *big.Int
}

// RecipientParams mirrors the squads Recipient: public owner + nullifier pk and
// the 65-byte uncompressed P-256 viewing key (0x04 || x || y). Zeroed for a
// withdrawal (no recipient).
type RecipientParams struct {
	Owner           *big.Int
	NullifierPubkey *big.Int
	ViewingPubkey   [65]*big.Int
}

// ProposalParams mirrors the squads Proposal commitment fields.
type ProposalParams struct {
	Amount       *big.Int
	Recipient    *big.Int
	Blinding     *big.Int
	PublicAmount *big.Int
}

// ZoneParameters is the flat, pre-computed witness for the squads zone circuit.
// The prover does no hashing/encryption: the client computes every field
// (utxo hashes, the public-input hash, the recipient ciphertext, ...) and sends
// them here. NOutputs is 2 for a transfer and 1 for a withdrawal.
type ZoneParameters struct {
	NInputs  uint32
	NOutputs uint32

	Inputs []UtxoParams
	// InputsDummy flags Inputs[1..] (length NInputs-1, 0 or 1 per slot); nil
	// means every input is real. Inputs[0] cannot be a dummy: its nullifier
	// seeds the tx_viewing_sk KDF.
	InputsDummy      []*big.Int
	Outputs          []UtxoParams
	ExternalDataHash *big.Int

	Sender    SenderParams
	Recipient RecipientParams
	Proposal  ProposalParams

	EnableProposalHash *big.Int
	PublicAmount       *big.Int
	PublicInputHash    *big.Int
}
