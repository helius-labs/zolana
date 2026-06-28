package transfereddsaonly

import (
	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover/common"
)

// Variant selects which Solana-only spp_transaction instantiation to build. The
// three forms are mutually exclusive; using an enum keeps the invalid
// confidential+zone-authority combination unrepresentable.
type Variant int

const (
	// ConfidentialVariant is the default transact: output owners bind to public
	// pk_field tags; non-zone.
	ConfidentialVariant Variant = iota
	// ZoneVariant is the anonymous policy-zone transfer (zone_transact): owners are
	// free for a view tag and each non-dummy UTXO binds its zone_program_id.
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
// to the anonymous zone variant.
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

// selectConstructor picks the Solana-only rail circuit constructor for the
// variant.
func selectConstructor(v Variant) func(txcircuit.Shape) (*txcircuit.Circuit, error) {
	switch v {
	case ConfidentialVariant:
		return txcircuit.NewTransferConfidentialCircuit
	case ZoneAuthorityVariant:
		return txcircuit.NewTransferZoneAuthorityCircuit
	default:
		return txcircuit.NewTransferZoneCircuit
	}
}
