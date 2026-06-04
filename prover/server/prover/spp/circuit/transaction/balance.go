package transaction

import (
	"math/big"

	"light/light-prover/prover/spp/model"

	"github.com/consensys/gnark/frontend"
)

func assertBalanceConservation(
	api frontend.API,
	inputs []UtxoCircuitFields,
	outputs []UtxoCircuitFields,
	publicSolAmount frontend.Variable,
	publicSplAmount frontend.Variable,
	publicSplAssetPubkey frontend.Variable,
) {
	assertSigned64Range(api, publicSolAmount)
	assertSigned64Range(api, publicSplAmount)

	// SPL public movement cannot target the SOL asset ID.
	splAmountIsZero := api.IsZero(publicSplAmount)
	splAssetIsSol := api.IsZero(api.Sub(publicSplAssetPubkey, model.SpecSolAssetID))
	api.AssertIsEqual(api.Mul(api.Sub(1, splAmountIsZero), splAssetIsSol), 0)

	// Check every private asset plus SOL and the public SPL asset.
	keys := make([]frontend.Variable, 0, len(inputs)+len(outputs)+2)
	for _, input := range inputs {
		api.ToBinary(input.AssetAmount, 64)
		keys = append(keys, input.AssetID)
	}
	for _, output := range outputs {
		api.ToBinary(output.AssetAmount, 64)
		keys = append(keys, output.AssetID)
	}
	keys = append(keys, frontend.Variable(model.SpecSolAssetID), publicSplAssetPubkey)

	for _, key := range keys {
		inSum := frontend.Variable(0)
		for _, input := range inputs {
			match := api.IsZero(api.Sub(key, input.AssetID))
			inSum = api.Add(inSum, api.Mul(match, input.AssetAmount))
		}

		outSum := frontend.Variable(0)
		for _, output := range outputs {
			match := api.IsZero(api.Sub(key, output.AssetID))
			outSum = api.Add(outSum, api.Mul(match, output.AssetAmount))
		}

		solMatch := api.IsZero(api.Sub(key, model.SpecSolAssetID))
		splMatch := api.IsZero(api.Sub(key, publicSplAssetPubkey))
		adjustedIn := api.Add(
			inSum,
			api.Mul(solMatch, publicSolAmount),
			api.Mul(splMatch, publicSplAmount),
		)
		api.AssertIsEqual(adjustedIn, outSum)
	}
}

func assertSigned64Range(api frontend.API, value frontend.Variable) {
	shift := new(big.Int).Lsh(big.NewInt(1), 64)
	api.ToBinary(api.Add(value, shift), 65)
}
