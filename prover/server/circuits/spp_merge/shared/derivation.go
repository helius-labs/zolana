package shared

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Domain separators (32-bit ASCII tags) for the deterministic merge-output
// recovery scheme. Mirror DOMAIN_MERGE_OUTPUT_BLINDING_V1 /
// DOMAIN_MERGE_DUMMY_NULLIFIER in
// sdk-libs/transaction/src/instructions/merge.rs; the cross-language vectors
// are pinned in derivation_test.go.
const (
	// MergeOutputBlindingDomainV1 = "TMOB"
	MergeOutputBlindingDomainV1 = 0x544d4f42
	// MergeDummyNullifierDomain = "TMDN"
	MergeDummyNullifierDomain = 0x544d444e
	// MergeOutputKeyDomain = "TMOK"
	MergeOutputKeyDomain = 0x544d4f4b
	// MergeOutputCiphertextDomain = "TMOC"
	MergeOutputCiphertextDomain = 0x544d4f43
)

// MergeOutputCiphertextLen is the number of field elements the merge output
// ciphertext publishes: the amount and the two hash_bytes_32 chunks of the
// mint, the only output fields the owner cannot derive.
const MergeOutputCiphertextLen = 3

// MergeOutputBlinding derives the merged output's blinding from the owner's
// nullifier secret and the first (always real) input's single-use nullifier.
// The owner and any merger it authorizes know the nullifier secret. A sender
// who knows only a UTXO blinding cannot recompute this recovery value.
func MergeOutputBlinding(api frontend.API, nullifierSecret, firstNullifier frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		MergeOutputBlindingDomainV1, nullifierSecret, firstNullifier,
	})
}

// MergeOutputKey derives the per-merge encryption key from the owner's
// nullifier secret, separated by the first input's single-use nullifier, so no
// two merges share a key and the nullifier secret is never a cipher key itself.
func MergeOutputKey(api frontend.API, nullifierSecret, firstNullifier frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		MergeOutputKeyDomain, nullifierSecret, firstNullifier,
	})
}

// MergeOutputCiphertext encrypts the merged output's amount and mint chunks
// under MergeOutputKey. A merger holds the nullifier secret and can fold in a
// note the owner never saw; the published ciphertext lets the owner rebuild the
// output from the merge transaction alone.
//
// The key repeats when a failed merge is rebuilt on the same first nullifier,
// so the pad nonce is the per-proof random salt, not the nullifier.
func MergeOutputCiphertext(
	api frontend.API,
	nullifierSecret,
	firstNullifier,
	salt,
	amount frontend.Variable,
	mint [2]frontend.Variable,
) []frontend.Variable {
	// The auditor decodes these exact byte widths. Without these bounds, a
	// valid proof could encrypt a field value that has no 32-byte mint opening.
	api.ToBinary(mint[0], 31*8)
	api.ToBinary(mint[1], 8)
	ctr := gadget.PoseidonCtr{
		Domain: MergeOutputCiphertextDomain,
		Key:    MergeOutputKey(api, nullifierSecret, firstNullifier),
		Nonce:  salt,
	}
	plaintext := [MergeOutputCiphertextLen]frontend.Variable{amount, mint[0], mint[1]}
	return ctr.Encrypt(api, plaintext[:])
}

// MergeDummyNullifier derives the published nullifier of a dummy (padding)
// input slot from the owner's nullifier secret, the first real input's
// single-use nullifier, and the slot index. Seeding with the nullifier secret
// (held by the owner and its authorized merger) rather than an input blinding
// (also known to that UTXO's sender) keeps padding nullifiers indistinguishable
// from real ones, while the
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
