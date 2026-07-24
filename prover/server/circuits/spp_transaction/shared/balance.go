package shared

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

const (
	AmountBits       = 64
	signedAmountBits = AmountBits + 1
)

func AssertBalanceConservation(
	api frontend.API,
	inputs []UtxoCircuitFields,
	outputs []UtxoCircuitFields,
	publicAssets []frontend.Variable,
	publicAmounts []frontend.Variable,
) {
	if len(publicAssets) != len(publicAmounts) {
		panic("spp: public asset and amount slot counts must match")
	}

	amountIsZero := make([]frontend.Variable, len(publicAmounts))
	for i, amount := range publicAmounts {
		rangeCheckSigned64(api, amount)
		amountIsZero[i] = api.IsZero(amount)
		// An asset id is public only while it moves; pin idle slots to 0 so a
		// pure-private transfer reveals no asset id in the public transcript
		// (the asset is otherwise a private per-UTXO field).
		assertZeroWhen(api, amountIsZero[i], publicAssets[i])
	}

	// Active slots must name distinct assets so each public movement maps to
	// exactly one settlement leg.
	for i := 0; i < len(publicAssets); i++ {
		for j := i + 1; j < len(publicAssets); j++ {
			bothActive := api.Mul(api.Sub(1, amountIsZero[i]), api.Sub(1, amountIsZero[j]))
			sameAsset := api.IsZero(api.Sub(publicAssets[i], publicAssets[j]))
			api.AssertIsEqual(api.Mul(bothActive, sameAsset), 0)
		}
	}

	// Check every private asset plus every public slot asset.
	keys := make([]frontend.Variable, 0, len(inputs)+len(outputs)+len(publicAssets))
	for _, input := range inputs {
		rangeCheck64(api, input.Amount)
		keys = append(keys, input.Asset)
	}
	for _, output := range outputs {
		rangeCheck64(api, output.Amount)
		keys = append(keys, output.Asset)
	}
	// Asset IDs are witness values; Go cannot dedup them safely.
	keys = append(keys, publicAssets...)

	for _, key := range keys {
		inSum := frontend.Variable(0)
		for _, input := range inputs {
			match := api.IsZero(api.Sub(key, input.Asset))
			inSum = api.Add(inSum, api.Mul(match, input.Amount))
		}

		outSum := frontend.Variable(0)
		for _, output := range outputs {
			match := api.IsZero(api.Sub(key, output.Asset))
			outSum = api.Add(outSum, api.Mul(match, output.Amount))
		}

		adjustedIn := inSum
		for i, asset := range publicAssets {
			match := api.IsZero(api.Sub(key, asset))
			adjustedIn = api.Add(adjustedIn, api.Mul(match, publicAmounts[i]))
		}
		api.AssertIsEqual(adjustedIn, outSum)
	}
}

// RangeCheck64 constrains value to fit in AmountBits (unsigned 64-bit).
type RangeCheck64 struct {
	Value frontend.Variable
}

func (gadget RangeCheck64) DefineGadget(api frontend.API) interface{} {
	api.ToBinary(gadget.Value, AmountBits)
	return []frontend.Variable{}
}

func rangeCheck64(api frontend.API, value frontend.Variable) {
	abstractor.CallVoid(api, RangeCheck64{Value: value})
}

// RangeCheckSigned64 constrains value to a signed 64-bit range by shifting it
// into the unsigned domain before the bit decomposition.
type RangeCheckSigned64 struct {
	Value frontend.Variable
}

func (gadget RangeCheckSigned64) DefineGadget(api frontend.API) interface{} {
	api.ToBinary(api.Add(gadget.Value, signedAmountOffset()), signedAmountBits)
	return []frontend.Variable{}
}

func rangeCheckSigned64(api frontend.API, value frontend.Variable) {
	abstractor.CallVoid(api, RangeCheckSigned64{Value: value})
}

func signedAmountOffset() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), AmountBits)
}
