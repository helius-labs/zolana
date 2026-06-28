package protocol

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/poseidon"
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

// PrivateTxHash mirrors PrivateTxHashGadget. addressUtxoHashes is the address
// category (the UTXO hash of every address slot, 0 for real spends and padding);
// it has the same length as inputUtxoHashes.
func PrivateTxHash(
	inputUtxoHashes []*big.Int,
	outputUtxoHashes []*big.Int,
	addressUtxoHashes []*big.Int,
	externalDataHash *big.Int,
) (*big.Int, error) {
	inputChain, err := HashChain(inputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash input chain: %w", err)
	}
	outputChain, err := HashChain(outputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash output chain: %w", err)
	}
	addressChain, err := HashChain(addressUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash address chain: %w", err)
	}

	h, err := poseidon.Hash([]*big.Int{
		inputChain,
		outputChain,
		addressChain,
		externalDataHash,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash: %w", err)
	}
	return h, nil
}
