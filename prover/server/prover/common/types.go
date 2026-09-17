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

	// MergeReceiptCircuitType is the default merge without in-circuit nullifier
	// non-inclusion: the program checks the nullifiers against a verified
	// nullifier receipt instead. Same public input, separate proving system.
	MergeReceiptCircuitType CircuitType = "merge-receipt"

	// NullifierReceiptCircuitType proves batch non-inclusion of published
	// nullifiers against a nullifier tree root, with GKR-batched hashing and one
	// BSB22 commitment. Shapes 144 and 512, no outputs.
	NullifierReceiptCircuitType CircuitType = "nullifier-receipt"

	// CustomRingBaseCircuitType proves the custom ring's audit statement only.
	CustomRingBaseCircuitType CircuitType = "custom-ring-base"

	// CustomRingPolicyCircuitType folds the audit statement with policy
	// enforcement in one proof and one verification per transact.
	CustomRingPolicyCircuitType CircuitType = "custom-ring-policy"
)

const CustomRingPolicyKeyFile = "custom_ring_policy.key"

const CustomRingBaseKeyFile = "custom_ring_base.key"
