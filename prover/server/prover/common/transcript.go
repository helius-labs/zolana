package common

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

func HashFields(inputs []*big.Int) (*big.Int, error) {
	for _, input := range inputs {
		if input == nil || input.Sign() < 0 || input.Cmp(fr.Modulus()) >= 0 {
			return nil, fmt.Errorf("noncanonical hash input")
		}
	}
	return poseidon.Hash(inputs)
}

func HashChain4(inputs []*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return new(big.Int), nil
	}
	for _, input := range inputs {
		if input == nil || input.Sign() < 0 || input.Cmp(fr.Modulus()) >= 0 {
			return nil, fmt.Errorf("noncanonical chain input")
		}
	}
	hash := new(big.Int).Set(inputs[0])
	for start := 1; start < len(inputs); start += 3 {
		group := []*big.Int{hash, new(big.Int), new(big.Int), new(big.Int)}
		copy(group[1:], inputs[start:min(start+3, len(inputs))])
		var err error
		hash, err = HashFields(group)
		if err != nil {
			return nil, err
		}
	}
	return hash, nil
}

func RightHashChain(inputs []*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return new(big.Int), nil
	}
	for _, input := range inputs {
		if input == nil || input.Sign() < 0 || input.Cmp(fr.Modulus()) >= 0 {
			return nil, fmt.Errorf("noncanonical chain input")
		}
	}
	hash := new(big.Int).Set(inputs[len(inputs)-1])
	for index := len(inputs) - 2; index >= 0; index-- {
		var err error
		hash, err = HashFields([]*big.Int{inputs[index], hash})
		if err != nil {
			return nil, err
		}
	}
	return hash, nil
}
