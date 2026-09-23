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

	// CustomRingBaseCircuitType proves the custom ring's audit statement only.
	CustomRingBaseCircuitType CircuitType = "custom-ring-base"

	// CustomRingPolicyCircuitType folds the audit statement with policy
	// enforcement in one proof and one verification per transact.
	CustomRingPolicyCircuitType         CircuitType = "custom-ring-policy"
	CustomRingDelegatePolicyCircuitType CircuitType = "custom-ring-delegate-policy"

	// Windowed members must seal their successor counters for disclosure.
	CustomRingCompressedPolicyCircuitType CircuitType = "custom-ring-compressed-policy"

	// Key registration inserts a member's auditor-encrypted nullifier key at the cursor.
	CustomRingKeyRegisterCircuitType CircuitType = "custom-ring-register-key"

	// Deposit openings must be encrypted for the configured auditor.
	CustomRingDepositCircuitType CircuitType = "custom-ring-deposit"
)

const CustomRingPolicyKeyFile = "custom_ring_policy.key"
const CustomRingDelegatePolicyKeyFile = "custom_ring_delegate_policy.key"

const CustomRingBaseKeyFile = "custom_ring_base.key"

const CustomRingCompressedPolicyKeyFile = "custom_ring_compressed_policy.key"

const CustomRingKeyRegisterKeyFile = "custom_ring_register_key.key"
const CustomRingDepositKeyFile = "custom_ring_deposit.key"

var RingKeyFiles = map[CircuitType]string{
	CustomRingPolicyCircuitType:           CustomRingPolicyKeyFile,
	CustomRingBaseCircuitType:             CustomRingBaseKeyFile,
	CustomRingDelegatePolicyCircuitType:   CustomRingDelegatePolicyKeyFile,
	CustomRingCompressedPolicyCircuitType: CustomRingCompressedPolicyKeyFile,
	CustomRingKeyRegisterCircuitType:      CustomRingKeyRegisterKeyFile,
	CustomRingDepositCircuitType:          CustomRingDepositKeyFile,
}

func (c CircuitType) IsRing() bool {
	_, ok := RingKeyFiles[c]
	return ok
}
