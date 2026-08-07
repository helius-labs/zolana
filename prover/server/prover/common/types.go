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

	SquadsZoneCircuitType          CircuitType = "squads-zone"
	SquadsKeyEncryptionCircuitType CircuitType = "squads-key-encryption"

	// SquadsZoneFoldCircuitType folds several zone spends of one account into
	// one proof, lifting the per-shape input cap. The leg shape and leg count
	// pick the proving system, because the inner verifying key is compiled into
	// the outer circuit.
	SquadsZoneFoldCircuitType CircuitType = "squads-zone-fold"

	// SquadsKeyEncryptionFoldCircuitType folds several key-encryption legs into
	// one proof over a wider recipient set. The per-leg recipient count and leg
	// count pick the proving system.
	SquadsKeyEncryptionFoldCircuitType CircuitType = "squads-key-encryption-fold"
)
