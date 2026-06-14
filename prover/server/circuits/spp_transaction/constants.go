package transaction

import "math/big"

// These mirror the SPP protocol constants, kept in the circuits package so it
// depends on no host code (see circuits/CLAUDE.md). They must stay in sync with
// prover/spp/protocol.
const (
	// UtxoDomain is the domain tag folded into every UTXO commitment.
	UtxoDomain = 1
	// StateTreeHeight is the SPP state (UTXO) merkle tree height.
	StateTreeHeight = 26
	// NullifierTreeHeight is the SPP nullifier tree height.
	NullifierTreeHeight = 40
)

// solAssetValue is the UTXO asset field for native SOL: Poseidon(0, 0), the
// all-zero address encoded as a SolanaPkField. Precomputed so the circuits
// package needs no host Poseidon; protocol.SolAsset() is the source of truth.
var solAssetValue, _ = new(big.Int).SetString(
	"14744269619966411208579211824598458697587494354926760081771325075741142829156", 10)

// SolAsset returns the native-SOL asset field used in UTXO commitments.
func SolAsset() *big.Int {
	return new(big.Int).Set(solAssetValue)
}
