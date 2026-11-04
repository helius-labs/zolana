package transfereddsa

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
	// ConfidentialVariant is the default transact: output owners bind to public
	// pk_field tags; non-ring.
	ConfidentialVariant Variant = iota
	// RingVariant is the confidential policy-ring transfer (ring_transact):
	// input and output owners remain private and each real UTXO binds its
	// ring_program_id. Solana signer hashes still authorize private owner hashes.
	RingVariant
	// RingAuthorityVariant is the anonymous policy-ring transfer for
	// ring_authority_transact: the ring authority controls its ring-owned UTXOs, so
	// owners do not sign. No in-circuit signature and every input owner pk_field
	// kept private (omitted from the public input hash).
	RingAuthorityVariant
	// RingAuthorityExitVariant is the ring authority rail with outputs that may
	// leave the ring under a published owner tag.
	RingAuthorityExitVariant
)

// CircuitType maps the variant to its wire/key CircuitType string.
func (v Variant) CircuitType() common.CircuitType {
	switch v {
	case ConfidentialVariant:
		return common.TransferConfidentialCircuitType
	case RingAuthorityVariant:
		return common.TransferRingAuthorityCircuitType
	case RingAuthorityExitVariant:
		return common.TransferRingAuthorityExitCircuitType
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
	case common.TransferRingAuthorityExitCircuitType:
		return RingAuthorityExitVariant
	default:
		return RingVariant
	}
}

// newVariantCircuit builds the Solana-only rail circuit for the variant.
func newVariantCircuit(v Variant, shape txcircuit.Shape) (frontend.Circuit, error) {
	switch v {
	case ConfidentialVariant:
		return defaultring.NewDefaultRingConfidentialEddsaCircuit(shape)
	case RingAuthorityVariant:
		return customring.NewCustomRingAuthorityCircuit(shape)
	case RingAuthorityExitVariant:
		return customring.NewCustomRingAuthorityExitCircuit(shape)
	default:
		return customring.NewCustomRingConfidentialEddsaCircuit(shape)
	}
}
