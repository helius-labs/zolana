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

	// TransferRingAuthorityCircuitType is the anonymous policy-ring transfer used
	// by ring_authority_transact. The ring authority controls its ring-owned
	// UTXOs, so owners do not sign. Solana-only, no in-circuit signature, input
	// owner pk_fields kept private.
	TransferRingAuthorityCircuitType CircuitType = "transfer-ring-authority"

	// AggregateCircuitType batches SPP transaction proofs into a single
	// recursive proof. The ordered slot list picks the proving system, because
	// every slot's inner verifying key is compiled into the outer circuit.
	AggregateCircuitType CircuitType = "aggregate"

	// NullifierFoldCircuitType folds a consecutive run of nullifier-tree
	// appends into a single recursive proof. The tree height, inner batch size,
	// and run length pick the proving system.
	NullifierFoldCircuitType CircuitType = "nullifier-fold"

	// SwapTakeCircuitType is the swap program's take circuit. It is not an SPP
	// rail and has no transfer shape, so it appears only as a mixed-batch slot
	// beside the transfer legs it settles against.
	SwapTakeCircuitType CircuitType = "swap-take"

	MergeCircuitType CircuitType = "merge"

	// MergeChainCircuitType chains merge proofs into a tree so one transaction
	// collapses more than the merge circuit's eight inputs. The level shape
	// picks the proving system, because the inner verifying key and the tree are
	// both compiled into the outer circuit.
	MergeChainCircuitType CircuitType = "merge-chain"

	// MergeRingCircuitType is the policy-ring analog of the merge proof used by
	// merge_ring. Every input and the output share ring_program_id (matching the
	// CPI-calling ring), which is committed as a public input. Otherwise identical
	// to the default merge.
	MergeRingCircuitType CircuitType = "merge-ring"
)
