package shared

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

// Domain separators (32-bit ASCII tags) for the deterministic merge-output
// recovery scheme. Mirror DOMAIN_MERGE_OUTPUT_BLINDING_V1 /
// DOMAIN_MERGE_DUMMY_NULLIFIER in sdk-libs/keypair/src/merge.rs; the
// cross-language vectors are pinned in derivation_test.go.
const (
	// MergeOutputBlindingDomainV1 = "TMOB"
	MergeOutputBlindingDomainV1 = 0x544d4f42
	// MergeDummyNullifierDomain = "TMDN"
	MergeDummyNullifierDomain = 0x544d444e
)

// MergeOutputBlinding derives the merged output's blinding from the first
// (always real) input's blinding and its single-use nullifier. The wallet
// recovers the output by recomputing this value off-circuit.
func MergeOutputBlinding(api frontend.API, firstInputBlinding, firstNullifier frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		MergeOutputBlindingDomainV1, firstInputBlinding, firstNullifier,
	})
}

// MergeDummyNullifier derives the published nullifier of a dummy (padding)
// input slot from the first real input's private, commitment-bound blinding,
// its single-use nullifier, and the slot index. The private seed keeps padding
// nullifiers indistinguishable from real ones while the fixed derivation prevents
// a prover from placing an arbitrary wallet nullifier in a dummy slot.
func MergeDummyNullifier(
	api frontend.API,
	firstInputBlinding,
	firstNullifier frontend.Variable,
	slotIndex int,
) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		MergeDummyNullifierDomain, firstInputBlinding, firstNullifier, slotIndex,
	})
}
