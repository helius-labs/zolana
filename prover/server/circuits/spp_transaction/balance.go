package transaction

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

const (
	AmountBits       = 64
	signedAmountBits = AmountBits + 1
)

func assertBalanceConservation(
	api frontend.API,
	inputs []UtxoCircuitFields,
	outputs []UtxoCircuitFields,
	publicSolAmount frontend.Variable,
	publicSplAmount frontend.Variable,
	publicSplAssetPubkey frontend.Variable,
) {
	rangeCheckSigned64(api, publicSolAmount)
	rangeCheckSigned64(api, publicSplAmount)

	solAsset := SolAsset()

	// SPL public movement cannot target the SOL asset.
	splAmountIsZero := api.IsZero(publicSplAmount)
	splAssetIsSol := api.IsZero(api.Sub(publicSplAssetPubkey, solAsset))
	api.AssertIsEqual(api.Mul(api.Sub(1, splAmountIsZero), splAssetIsSol), 0)

	// The SPL mint id is public only when it moves; pin it to 0 otherwise so a
	// SOL-only or pure-private transfer reveals no asset id in the public
	// transcript (the asset is otherwise a private per-UTXO field).
	assertZeroWhen(api, splAmountIsZero, publicSplAssetPubkey)

	// Check every private asset plus SOL and the public SPL asset.
	keys := make([]frontend.Variable, 0, len(inputs)+len(outputs)+2)
	for _, input := range inputs {
		rangeCheck64(api, input.Amount)
		keys = append(keys, input.Asset)
	}
	for _, output := range outputs {
		rangeCheck64(api, output.Amount)
		keys = append(keys, output.Asset)
	}
	// Asset IDs are witness values; Go cannot dedup them safely.
	keys = append(keys, frontend.Variable(solAsset), publicSplAssetPubkey)

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

		solMatch := api.IsZero(api.Sub(key, solAsset))
		splMatch := api.IsZero(api.Sub(key, publicSplAssetPubkey))
		adjustedIn := api.Add(
			inSum,
			api.Mul(solMatch, publicSolAmount),
			api.Mul(splMatch, publicSplAmount),
		)
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
