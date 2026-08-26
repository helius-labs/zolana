package common

type CircuitType string

const (
	BatchAddressAppendCircuitType CircuitType = "address-append"

	TransferConfidentialCircuitType CircuitType = "transfer-confidential"

	// TransferRingCircuitType is the confidential policy-ring transfer.
	TransferRingCircuitType CircuitType = "transfer-ring"

	// TransferP256RingCircuitType is the custom-ring transfer with an in-circuit
	// P256 authorization shared by every P256-owned input.
	TransferP256RingCircuitType CircuitType = "transfer-p256-ring"

	// TransferRingAuthorityCircuitType is the anonymous policy-ring transfer used by
	// ring_authority_transact: the ring authority controls its ring-owned UTXOs, so
	// owners do not sign. Solana-only, no in-circuit signature, input owner
	// pk_fields kept private.
	TransferRingAuthorityCircuitType CircuitType = "transfer-ring-authority"

	MergeCircuitType CircuitType = "merge"

	// MergeRingCircuitType is the policy-ring analog of the merge proof used by
	// merge_ring: every input and the output share ring_program_id (matching the
	// CPI-calling ring), which is committed as a public input. Otherwise identical
	// to the default merge.
	MergeRingCircuitType CircuitType = "merge-ring"

	// CustomRingCircuitType proves the audit statement and the ring's rule
	// table in one proof, one verification per transact.
	CustomRingCircuitType CircuitType = "custom-ring"
)

const CustomRingKeyFile = "custom_ring.key"
