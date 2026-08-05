package common

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// HashChain folds Poseidon left to right, matching gadget.HashChain in circuit
// and create_hash_chain_from_slice on chain. The fold is order sensitive, so a
// permutation is a different value.
func HashChain(values []*big.Int) (*big.Int, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("empty hash chain")
	}
	acc := values[0]
	for _, next := range values[1:] {
		folded, err := poseidon.Hash([]*big.Int{acc, next})
		if err != nil {
			return nil, fmt.Errorf("hash chain: %w", err)
		}
		acc = folded
	}
	return acc, nil
}

// SinglePublicInput reads the one public input of a proof every circuit here
// exposes.
func SinglePublicInput(public witness.Witness) (*big.Int, error) {
	vector, ok := public.Vector().(fr.Vector)
	if !ok {
		return nil, fmt.Errorf("public witness is %T, want a BN254 vector", public.Vector())
	}
	if len(vector) != 1 {
		return nil, fmt.Errorf("%d public inputs, want 1", len(vector))
	}
	value := new(big.Int)
	vector[0].BigInt(value)
	return value, nil
}
