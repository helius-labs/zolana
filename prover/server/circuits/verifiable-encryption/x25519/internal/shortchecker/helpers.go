package shortchecker

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/internal/emfield"
	"github.com/helius-labs/zolana/prover/server/circuits/internal/shortladder"
)

var pow2 = shortladder.Pow2
var modRatio = shortladder.ModRatio
var prime = shortladder.Prime
var offset = shortladder.Offset
var coefficients = shortladder.Coefficients

// rangeChecker returns the field's shared range checker. Its deferred lookup
// checks are part of the compiled circuit and must not be omitted.
func (c *curve) rangeChecker() *emfield.RangeChecker {
	return c.fp.RangeChecker()
}

// limbHintInputs prefixes limbs with their public radix for witness generation.
// It adds no constraints and requires the caller to establish limb bounds.
func (c *curve) limbHintInputs(limbs []frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{c.lay.LimbBits}, limbs...)
}

// limbHintValue reconstructs a host integer from unsigned little-endian limbs.
// The header is supplied by the circuit. This helper does not validate a witness.
func limbHintValue(inputs []*big.Int) *big.Int {
	return shortladder.Integer(inputs[1:], int(inputs[0].Uint64()))
}
