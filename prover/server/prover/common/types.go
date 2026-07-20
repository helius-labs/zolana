package common

type CircuitType string

const (
	BatchAddressAppendCircuitType CircuitType = "address-append"

	TransferP256ConfidentialCircuitType CircuitType = "transfer-p256-confidential"
	TransferConfidentialCircuitType     CircuitType = "transfer-confidential"

	// Policy zones are anonymous, so the zone variants have no confidential form.
	TransferP256ZoneCircuitType CircuitType = "transfer-p256-zone"
	TransferZoneCircuitType     CircuitType = "transfer-zone"

	// TransferZoneAuthorityCircuitType is the anonymous policy-zone transfer used by
	// zone_authority_transact: the zone authority controls its zone-owned UTXOs, so
	// owners do not sign. Solana-only, no in-circuit signature, input owner
	// pk_fields kept private. P256 has no zone-authority form (the rail exists only
	// to verify a signature, which this variant omits).
	TransferZoneAuthorityCircuitType CircuitType = "transfer-zone-authority"

	MergeCircuitType CircuitType = "merge"

	// MergeZoneCircuitType is the policy-zone analog of the merge proof used by
	// merge_zone: every input and the output share zone_program_id (matching the
	// CPI-calling zone), which is committed as a public input. Otherwise identical
	// to the default merge.
	MergeZoneCircuitType CircuitType = "merge-zone"
)
