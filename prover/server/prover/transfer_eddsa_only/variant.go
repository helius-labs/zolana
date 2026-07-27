package transfereddsaonly

import (
	customzone "zolana/prover/circuits/spp_transaction/custom"
	defaultzone "zolana/prover/circuits/spp_transaction/default"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark/frontend"
)

// Variant selects which Solana-only spp_transaction instantiation to build. The
// three forms are mutually exclusive.
type Variant int

const (
	// ConfidentialVariant is the default transact: output owners bind to public
	// pk_field tags; non-zone.
	ConfidentialVariant Variant = iota
	// ZoneVariant is the confidential policy-zone transfer (zone_transact):
	// input and output owners bind to public tags and each real UTXO binds its
	// zone_program_id.
	ZoneVariant
	// ZoneAuthorityVariant is the anonymous policy-zone transfer for
	// zone_authority_transact: the zone authority controls its zone-owned UTXOs, so
	// owners do not sign. No in-circuit signature and every input owner pk_field
	// kept private (omitted from the public input hash).
	ZoneAuthorityVariant
)

// CircuitType maps the variant to its wire/key CircuitType string.
func (v Variant) CircuitType() common.CircuitType {
	switch v {
	case ConfidentialVariant:
		return common.TransferConfidentialCircuitType
	case ZoneAuthorityVariant:
		return common.TransferZoneAuthorityCircuitType
	default:
		return common.TransferZoneCircuitType
	}
}

// variantFromCircuitType is the inverse of Variant.CircuitType; unknown types map
// to the confidential zone variant.
func variantFromCircuitType(ct common.CircuitType) Variant {
	switch ct {
	case common.TransferConfidentialCircuitType:
		return ConfidentialVariant
	case common.TransferZoneAuthorityCircuitType:
		return ZoneAuthorityVariant
	default:
		return ZoneVariant
	}
}

// newVariantCircuit builds the Solana-only rail circuit for the variant.
func newVariantCircuit(v Variant, shape txcircuit.Shape) (frontend.Circuit, error) {
	switch v {
	case ConfidentialVariant:
		return defaultzone.NewDefaultZoneEddsaOnlyCircuit(shape)
	case ZoneAuthorityVariant:
		return customzone.NewCustomZoneAuthorityCircuit(shape)
	default:
		return customzone.NewCustomZoneEddsaOnlyCircuit(shape)
	}
}
