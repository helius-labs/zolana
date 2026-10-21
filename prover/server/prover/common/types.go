package common

type CircuitType string

const (
	BatchAddressAppendCircuitType CircuitType = "address-append"

	TransferConfidentialCircuitType CircuitType = "transfer-confidential"

	// TransferRingCircuitType is the confidential policy-ring transfer.
	TransferRingCircuitType CircuitType = "transfer-ring"

	// TransferAnonymousRingEddsaCircuitType is the custom-ring transfer with an
	// in-circuit Ed25519 authorization shared by every hidden-owner input.
	TransferAnonymousRingEddsaCircuitType CircuitType = "transfer-eddsa-ring"

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

	// CustomRingKeyRegisterCircuitType seals a member's nullifier secret to the auditor.
	CustomRingKeyRegisterCircuitType CircuitType = "custom-ring-register-key"

	// CustomRingDepositCircuitType binds every deposited owner to an opening sealed to the auditor.
	CustomRingDepositCircuitType CircuitType = "custom-ring-deposit"
)

func (c CircuitType) IsRing() bool {
	_, ok := RingKeyOf(c)
	return ok
}
