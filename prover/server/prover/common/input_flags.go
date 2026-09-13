package common

import (
	"fmt"
	"math/big"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
)

// PackInputFlags builds the InputFlags public input element: bit 0 is the
// dummy-input policy and input i's tree index occupies the TreeIndexBits bits
// starting at 1+TreeIndexBits*i. treeIndexes holds one index per input, in
// input order, so the packed width is 1+TreeIndexBits*len(treeIndexes) bits.
// The circuit decodes the same layout (Transaction.Constrain) and binds each
// field back to the input's private tree slot selection.
func PackInputFlags(allowDummyInputs bool, treeIndexes []*big.Int) (*big.Int, error) {
	flags := big.NewInt(0)
	if allowDummyInputs {
		flags.SetInt64(1)
	}
	for i, index := range treeIndexes {
		if index == nil || index.Sign() < 0 || index.BitLen() > txcircuit.TreeIndexBits {
			return nil, fmt.Errorf(
				"spp: input %d tree index %v does not fit in %d bits",
				i, index, txcircuit.TreeIndexBits,
			)
		}
		flags.Or(flags, new(big.Int).Lsh(index, uint(1+txcircuit.TreeIndexBits*i)))
	}
	return flags, nil
}

// ValidateInputFlags checks that the request's packed InputFlags publishes
// exactly the per-input tree indexes the request also sends as the private
// slot selectors, and carries nothing above the packed width. The circuit
// asserts the same, so failing here turns an opaque proving error into a
// request error.
func ValidateInputFlags(inputFlags *big.Int, inputSlots []*big.Int) error {
	if inputFlags == nil {
		return fmt.Errorf("spp: inputFlags is required")
	}
	if inputFlags.Sign() < 0 {
		return fmt.Errorf("spp: inputFlags %v is negative", inputFlags)
	}
	want, err := PackInputFlags(inputFlags.Bit(0) == 1, inputSlots)
	if err != nil {
		return err
	}
	if inputFlags.Cmp(want) != 0 {
		return fmt.Errorf(
			"spp: inputFlags 0x%s does not pack the per-input tree slots (want 0x%s)",
			inputFlags.Text(16), want.Text(16),
		)
	}
	return nil
}
