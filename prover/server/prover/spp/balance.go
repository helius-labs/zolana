package spp

import (
	"github.com/consensys/gnark/frontend"
)

// SpecSolAssetID is the SPP asset_id reserved by the spec for native SOL.
const SpecSolAssetID = 1

func assertBalanceConservation(
	api frontend.API,
	inputs []UtxoCircuitFields,
	outputs []UtxoCircuitFields,
	publicSolAmount frontend.Variable,
	publicSplAmount frontend.Variable,
	publicSplAssetPubkey frontend.Variable,
) {
	// publicSolAmount / publicSplAmount arrive as signed values already derived
	// in Circuit.Define from range-checked raw magnitudes, so no further range
	// check is needed here; their magnitudes stay far below the field modulus.

	// SPL public movement must not use the SOL-reserved asset field.
	splAmountIsZero := api.IsZero(publicSplAmount)
	splAssetIsSol := api.IsZero(api.Sub(publicSplAssetPubkey, SpecSolAssetID))
	api.AssertIsEqual(api.Mul(api.Sub(1, splAmountIsZero), splAssetIsSol), 0)

	// Spec rule: for each active asset, inputs plus public deposits equal
	// outputs plus public withdrawals and fees. Native SOL is asset_id = 1;
	// SPL assets use the canonical mint-derived public_spl_asset_pubkey field.
	keys := make([]frontend.Variable, 0, len(inputs)+len(outputs)+2)
	for _, input := range inputs {
		api.ToBinary(input.AssetAmount, 64)
		keys = append(keys, input.AssetID)
	}
	for _, output := range outputs {
		api.ToBinary(output.AssetAmount, 64)
		keys = append(keys, output.AssetID)
	}
	keys = append(keys, frontend.Variable(SpecSolAssetID), publicSplAssetPubkey)

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

		solMatch := api.IsZero(api.Sub(key, SpecSolAssetID))
		splMatch := api.IsZero(api.Sub(key, publicSplAssetPubkey))
		adjustedIn := api.Add(
			inSum,
			api.Mul(solMatch, publicSolAmount),
			api.Mul(splMatch, publicSplAmount),
		)
		api.AssertIsEqual(adjustedIn, outSum)
	}
}
