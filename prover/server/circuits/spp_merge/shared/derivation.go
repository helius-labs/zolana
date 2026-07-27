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

// MergeOutputBlinding derives the merged output's blinding from the owner's
// nullifier secret and the first (always real) input's single-use nullifier.
// The nullifier secret is known to the owner alone -- unlike a UTXO blinding,
// which the sender of that UTXO also knows -- so only the owner can recompute
// this value off-circuit to recover the output.
func MergeOutputBlinding(api frontend.API, nullifierSecret, firstNullifier frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		MergeOutputBlindingDomainV1, nullifierSecret, firstNullifier,
	})
}

// MergeDummyNullifier derives the published nullifier of a dummy (padding)
// input slot from the owner's nullifier secret, the first real input's
// single-use nullifier, and the slot index. Seeding with the nullifier secret
// (owner-only) rather than an input blinding (also known to that UTXO's
// sender) keeps padding nullifiers indistinguishable from real ones, while the
// fixed derivation prevents a prover from placing an arbitrary wallet
// nullifier in a dummy slot.
func MergeDummyNullifier(
	api frontend.API,
	nullifierSecret,
	firstNullifier frontend.Variable,
	slotIndex int,
) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		MergeDummyNullifierDomain, nullifierSecret, firstNullifier, slotIndex,
	})
}
