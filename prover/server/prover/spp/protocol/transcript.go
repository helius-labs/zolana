package protocol

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/poseidon"
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

func PrivateTxHash(
	inputUtxoHashes []*big.Int,
	outputUtxoHashes []*big.Int,
	externalDataHash *big.Int,
	expiryUnixTs *big.Int,
) (*big.Int, error) {
	inputChain, err := HashChain(inputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash input chain: %w", err)
	}
	outputChain, err := HashChain(outputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash output chain: %w", err)
	}

	h, err := poseidon.Hash([]*big.Int{
		inputChain,
		outputChain,
		externalDataHash,
		expiryUnixTs,
	})
	if err != nil {
		return nil, fmt.Errorf("spp: private tx hash: %w", err)
	}
	return h, nil
}
