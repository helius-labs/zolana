package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover/common"
)

// HashChain folds values from left to right:
//
//	h = inputs[0]
//	for i = 1; i < len(inputs); i++:
//	    h = Poseidon(h, inputs[i])
func HashChain(inputs []*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return new(big.Int), nil
	}
	for i, input := range inputs {
		if err := validateFieldElement(fmt.Sprintf("input[%d]", i), input); err != nil {
			return nil, fmt.Errorf("spp: hash chain: %w", err)
		}
	}

	h := new(big.Int).Set(inputs[0])
	for i := 1; i < len(inputs); i++ {
		next, err := poseidon.Hash([]*big.Int{h, inputs[i]})
		if err != nil {
			return nil, fmt.Errorf("spp: hash chain step %d: %w", i, err)
		}
		h = next
	}
	return h, nil
}

// HashChain4 folds values from left to right three at a time:
//
//	h = inputs[0]
//	for each group g of up to 3 consecutive elements of inputs[1:]:
//	    h = Poseidon(h, g[0], g[1] or 0, g[2] or 0)
//
// Every call is the 4-input permutation; a short trailing group is zero
// padded. Only chains whose length the compiled circuit fixes may use it.
func HashChain4(inputs []*big.Int) (*big.Int, error) {
	return common.HashChain4(inputs)
}

// RightHashChain folds values from right to left. The fixed-width signer
// transcript uses this direction so the on-chain verifier can start from a
// precomputed all-zero suffix.
func RightHashChain(inputs []*big.Int) (*big.Int, error) {
	return common.RightHashChain(inputs)
}

// PrivateTxHash mirrors PrivateTxHashGadget. addressNullifiers is the address
// category (the nullifier, i.e. the compressed address, of every address slot;
// 0 for real spends and padding); it has the same length as inputUtxoHashes.
// blinding is the transaction's private blinding, which the circuit rejects
// when zero.
func PrivateTxHash(
	inputUtxoHashes []*big.Int,
	outputUtxoHashes []*big.Int,
	addressNullifiers []*big.Int,
	externalDataHash *big.Int,
	blinding *big.Int,
) (*big.Int, error) {
	inputChain, err := HashChain4(inputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash input chain: %w", err)
	}
	outputChain, err := HashChain4(outputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash output chain: %w", err)
	}
	addressChain, err := HashChain4(addressNullifiers)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash address chain: %w", err)
	}

	h, err := poseidon.Hash([]*big.Int{
		inputChain,
		outputChain,
		addressChain,
		externalDataHash,
		blinding,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash: %w", err)
	}
	return h, nil
}
