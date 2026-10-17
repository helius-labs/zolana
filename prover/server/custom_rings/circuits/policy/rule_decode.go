package policy

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

func init() { solver.RegisterHint(rulePartsHint) }

// decodeRuleCompact decomposes only list masks into individual bits. The
// threshold and tag bytes use lookup bounds. Recomposition is below 2^104,
// so it uniquely binds all parts to the packed rule without field aliases.
func decodeRuleCompact(api frontend.API, packed frontend.Variable) ruleFields {
	w, err := api.Compiler().NewHint(rulePartsHint, 6, packed)
	if err != nil {
		panic(err)
	}
	rc := rangecheck.New(api)
	for _, index := range []int{0, 1, 3} {
		rc.Check(w[index], 8)
	}
	rc.Check(w[4], 64)
	listBits, altBits := api.ToBinary(w[2], 8), api.ToBinary(w[5], 8)
	var encoded frontend.Variable = 0
	for i, shift := range []uint{0, 8, 16, 24, 32, 96} {
		encoded = api.Add(encoded, api.Mul(w[i], new(big.Int).Lsh(big.NewInt(1), shift)))
	}
	api.AssertIsEqual(encoded, packed)
	is := func(value frontend.Variable, want int) frontend.Variable { return api.IsZero(api.Sub(value, want)) }
	return ruleFields{
		mode: w[1], threshold: w[4], altMask: w[5], listBits: listBits, altBits: altBits,
		onOwner: is(w[0], SubjectOutputOwner), onAsset: is(w[0], SubjectAsset), onSender: is(w[0], SubjectSender),
		present: is(w[1], ModePresent), absent: is(w[1], ModeAbsent), inline: api.IsZero(w[2]),
		hasAlternative: base.NonZero(api, w[5]),
		always:         is(w[3], GuardAlways), scalarGuard: is(w[3], GuardAboveAmount), assetGuard: is(w[3], GuardAboveAmountByAsset),
	}
}

func rulePartsHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) != 6 {
		return fmt.Errorf("rule parts: expected 1 input and 6 outputs")
	}
	for i, shift := range []uint{0, 8, 16, 24, 32, 96} {
		width := uint(8)
		if i == 4 {
			width = 64
		}
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
		outputs[i].Rsh(inputs[0], shift).And(outputs[i], mask)
	}
	return nil
}
