package shared

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
)

const (
	MergeOutputBlindingDomainV1 = 0x544d4f42
	MergeDummyNullifierDomain   = 0x544d444e
	MergeDerivedBlindingDomain  = 0x544d4542

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

func MergeOutputBlinding(api frontend.API, nullifierSecret, firstNullifier frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		MergeOutputBlindingDomainV1, nullifierSecret, firstNullifier,
	})
}

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

func MergePlaintext(api frontend.API, amount frontend.Variable, mintChunks [MintChunkCount]frontend.Variable) []frontend.Variable {
	plaintext := make([]frontend.Variable, 0, MergeCiphertextBytes)
	plaintext = append(plaintext, ve.BytesBigEndian(api, amount, MergeAmountBytes)...)
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
		ve.BytesToField(api, head),
	)
	return [4]frontend.Variable{
		encrypted.RecipientLo,
		encrypted.EphemeralLo,
		packed,
		ve.BytesToField(api, tail),
	}
}
