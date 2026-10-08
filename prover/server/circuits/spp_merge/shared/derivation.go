package shared

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
)

// Domain separators (32-bit ASCII tags) for the deterministic merge-output
// recovery scheme. Mirror DOMAIN_MERGE_OUTPUT_BLINDING_V1 /
// DOMAIN_MERGE_DUMMY_NULLIFIER in
// sdk-libs/transaction/src/instructions/merge/blinding.rs; the cross-language vectors
// are pinned in derivation_test.go.
const (
	// MergeOutputBlindingDomainV1 = "TMOB"
	MergeOutputBlindingDomainV1 = 0x544d4f42
	// MergeDummyNullifierDomain = "TMDN"
	MergeDummyNullifierDomain  = 0x544d444e
	MergeDerivedBlindingDomain = 0x544d4542

	MergeAmountBytes              = 8
	MergeCiphertextBytes          = MergeAmountBytes + MintHeadChunkBytes + MintTailChunkBytes
	MergeHeadChunkCiphertextBytes = 27
	MintChunkCount                = 2
	MintHeadChunkBytes            = 31
	MintTailChunkBytes            = 1
)

var (
	MergeSecretTag = []byte("TMES")
	MergeKdfInfo   = []byte("TMEC")
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

func MergeDerivedBlinding(api frontend.API, sharedSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{MergeDerivedBlindingDomain, sharedSecret})
}

func MergePlaintext(api frontend.API, amountBytes []frontend.Variable, mintChunks [MintChunkCount]frontend.Variable) []frontend.Variable {
	plaintext := make([]frontend.Variable, 0, MergeCiphertextBytes)
	plaintext = append(plaintext, amountBytes...)
	plaintext = append(plaintext, ve.BytesBigEndian(api, mintChunks[0], MintHeadChunkBytes)...)
	plaintext = append(plaintext, ve.BytesBigEndian(api, mintChunks[1], MintTailChunkBytes)...)
	return plaintext
}

func EnvelopePublicElements(api frontend.API, encrypted ve.Encrypted) [4]frontend.Variable {
	ciphertext := encrypted.Ciphertext
	head := ciphertext[:MergeHeadChunkCiphertextBytes]
	tail := ciphertext[MergeHeadChunkCiphertextBytes:MergeCiphertextBytes]
	recipientShift := new(big.Int).Lsh(big.NewInt(1), 8*(2+MergeHeadChunkCiphertextBytes))
	ephemeralShift := new(big.Int).Lsh(big.NewInt(1), 8*MergeHeadChunkCiphertextBytes)
	packed := api.Add(
		api.Mul(encrypted.RecipientHi, recipientShift),
		api.Mul(encrypted.EphemeralHi, ephemeralShift),
		gadget.BytesToField(api, head),
	)
	return [4]frontend.Variable{
		encrypted.RecipientLo,
		encrypted.EphemeralLo,
		packed,
		gadget.BytesToField(api, tail),
	}
}
