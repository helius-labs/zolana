package common

type CircuitType string

const (
	BatchAddressAppendCircuitType CircuitType = "address-append"

	TransferConfidentialCircuitType CircuitType = "transfer-confidential"

	// TransferZoneCircuitType is the confidential policy-zone transfer.
	TransferZoneCircuitType CircuitType = "transfer-zone"

	// TransferP256ZoneCircuitType is the custom-zone transfer with an in-circuit
	// P256 authorization shared by every P256-owned input.
	TransferP256ZoneCircuitType CircuitType = "transfer-p256-zone"

	// TransferZoneAuthorityCircuitType is the anonymous policy-zone transfer used by
	// zone_authority_transact: the zone authority controls its zone-owned UTXOs, so
	// owners do not sign. Solana-only, no in-circuit signature, input owner
	// pk_fields kept private.
	TransferZoneAuthorityCircuitType CircuitType = "transfer-zone-authority"

	MergeCircuitType CircuitType = "merge"

	// MergeZoneCircuitType is the policy-zone analog of the merge proof used by
	// merge_zone: every input and the output share zone_program_id (matching the
	// CPI-calling zone), which is committed as a public input. Otherwise identical
	// to the default merge.
	MergeZoneCircuitType CircuitType = "merge-zone"
)
