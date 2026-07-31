package transfereddsaonly

import (
	customring "zolana/prover/circuits/spp_transaction/custom"
	defaultring "zolana/prover/circuits/spp_transaction/default"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"

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
		return defaultring.NewDefaultRingEddsaOnlyCircuit(shape)
	case RingAuthorityVariant:
		return customring.NewCustomRingAuthorityCircuit(shape)
	default:
		return customring.NewCustomRingEddsaOnlyCircuit(shape)
	}
}
