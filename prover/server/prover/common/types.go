package common

import (
	"slices"
	"strings"
)

type CircuitType string

const (
	BatchAddressAppendCircuitType CircuitType = "address-append"

	TransferConfidentialCircuitType CircuitType = "transfer-confidential"

	// TransferRingCircuitType is the confidential policy-ring transfer.
	TransferRingCircuitType CircuitType = "transfer-ring"

	// TransferAnonymousRingEd25519CircuitType hides senders, recipients, amounts
	// and assets in custom-ring transfers. The wire identifier remains stable.
	TransferAnonymousRingEd25519CircuitType CircuitType = "transfer-ed25519-ring"

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

	// Key registration writes a member's auditor-encrypted nullifier key into its record.
	CustomRingKeyRegisterCircuitType CircuitType = "custom-ring-register-key"

	// A batch of member record updates against the ring's member registry.
	CustomRingUpdateMembersCircuitType CircuitType = "custom-ring-update-members"

	// Deposit openings must be encrypted for the configured auditor.
	CustomRingDepositCircuitType CircuitType = "custom-ring-deposit"
)

// RingCircuitTypes are the custom-ring circuits, each proven with one key.
var RingCircuitTypes = []CircuitType{
	CustomRingPolicyCircuitType,
	CustomRingBaseCircuitType,
	CustomRingDelegatePolicyCircuitType,
	CustomRingKeyRegisterCircuitType,
	CustomRingDepositCircuitType,
	CustomRingUpdateMembersCircuitType,
}

func (c CircuitType) IsRing() bool {
	return slices.Contains(RingCircuitTypes, c)
}

// RingKeyFile names a custom-ring circuit's key file, or "" for none.
func RingKeyFile(c CircuitType) string {
	if !c.IsRing() {
		return ""
	}
	return strings.ReplaceAll(string(c), "-", "_") + ".key"
}
