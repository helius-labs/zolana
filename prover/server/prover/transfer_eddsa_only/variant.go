package transfereddsaonly

import (
	"fmt"

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
	// ConfidentialVariant is the default transact. Output owners bind to public
	// pk_field tags. Non-ring.
	ConfidentialVariant Variant = iota
	// RingVariant is the confidential policy-ring transfer (ring_transact).
	// Input and output owners remain private and each real UTXO binds its
	// ring_program_id. Solana signer hashes still authorize private owner hashes.
	RingVariant
	// RingAuthorityVariant is the anonymous policy-ring transfer for
	// ring_authority_transact. The ring authority controls its ring-owned UTXOs, so
	// owners do not sign. No in-circuit signature, and every input owner pk_field
	// stays private (omitted from the public input hash).
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

// VariantFromCircuitType is the inverse of Variant.CircuitType. A type that
// names no Solana-only rail is rejected rather than defaulted, so a mistyped
// request cannot prove a different circuit than it asked for.
func VariantFromCircuitType(ct common.CircuitType) (Variant, error) {
	switch ct {
	case common.TransferConfidentialCircuitType:
		return ConfidentialVariant, nil
	case common.TransferRingCircuitType:
		return RingVariant, nil
	case common.TransferRingAuthorityCircuitType:
		return RingAuthorityVariant, nil
	default:
		return 0, fmt.Errorf("circuit type %q names no eddsa rail", ct)
	}
}

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
