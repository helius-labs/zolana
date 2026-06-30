package transfer

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

// TransferParameters is the flat, pre-computed witness for the P256-capable
// spp_transaction circuit. The prover does no hashing: the client computes every
// field (utxo hashes, nullifiers, tree roots/proofs, the private-tx hash, the
// public-input hash, ...) and sends them here.
type TransferParameters struct {
	NInputs  uint32
	NOutputs uint32

	Inputs  []InputParams
	Outputs []OutputParams

	ExternalDataHash *big.Int

	// P256 ownership witness (P256-capable rail only).
	P256PubX *big.Int
	P256PubY *big.Int
	P256SigR *big.Int
	P256SigS *big.Int

	PrivateTxHash *big.Int
	// P256 ECDSA message digest (full SHA-256) as two big-endian 128-bit limbs.
	// Both 0 on the Solana-only rail.
	P256MessageHashLow   *big.Int
	P256MessageHashHigh  *big.Int
	PublicSolAmount      *big.Int
	PublicSplAmount      *big.Int
	PublicSplAssetPubkey *big.Int
	ZoneProgramID        *big.Int
	PayerPubkeyHash      *big.Int

	// Confidential selects the confidential (non-zone) variant; when false the
	// anonymous zone variant is used. P256SigningPkField is the shared P256
	// signing key's pk_field (0 otherwise).
	Confidential       bool
	P256SigningPkField *big.Int

	PublicInputHash *big.Int
}
