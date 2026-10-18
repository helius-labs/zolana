package transfereddsaonly

import (
	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	defaultring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/default"
	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"

	"github.com/consensys/gnark/frontend"
)

// Variant selects which Solana-only spp_transaction instantiation to build. The
// three forms are mutually exclusive.
type Variant int

const (
	// ConfidentialVariant is the default transfer. Output owners bind to
	// published owner tags.
	ConfidentialVariant Variant = iota
	// RingVariant is the confidential policy-ring transfer. Input and output
	// owners remain private, each real UTXO binds its ring program, and Solana
	// signer hashes authorize private owner hashes.
	RingVariant
	// RingAuthorityVariant is the anonymous policy-ring transfer for
	// authority rail. The ring authority controls its ring-owned UTXOs, so
	// owners do not sign. Input owner tags remain private and are omitted from
	// the public input hash.
	RingAuthorityVariant
)

// CircuitType maps the variant to its wire/key CircuitType string.
func (v Variant) CircuitType() common.CircuitType {
	switch v {
	case ConfidentialVariant:
		return common.TransferConfidentialCircuitType
	case RingAuthorityVariant:
		return common.TransferRingAuthorityCircuitType
	default:
		return common.TransferRingCircuitType
	}
}

// variantFromCircuitType is the inverse of Variant.CircuitType; unknown types map
// to the confidential ring variant.
func variantFromCircuitType(ct common.CircuitType) Variant {
	switch ct {
	case common.TransferConfidentialCircuitType:
		return ConfidentialVariant
	case common.TransferRingAuthorityCircuitType:
		return RingAuthorityVariant
	default:
		return RingVariant
	}
}

// newVariantCircuit builds the Solana-only rail circuit for the variant.
func newVariantCircuit(v Variant, shape txcircuit.Shape) (frontend.Circuit, error) {
	switch v {
	case ConfidentialVariant:
		return defaultring.NewDefaultRingConfidentialEd25519Circuit(shape)
	case RingAuthorityVariant:
		return customring.NewCustomRingAuthorityCircuit(shape)
	default:
		return customring.NewCustomRingConfidentialEd25519Circuit(shape)
	}
}
