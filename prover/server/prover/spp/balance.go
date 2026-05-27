package spp

import (
	"math/big"

	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

// SpecSolAssetID is the SPP asset_id reserved by the spec for native SOL.
const SpecSolAssetID = 1

// SignedToFe maps signed public amounts into their canonical BN254 Fr
// representative. Positive values pass through; negative values become
// modulus - |value|.
func SignedToFe(value *big.Int) *big.Int {
	return new(big.Int).Mod(value, poseidon.Modulus)
}

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

	// SPL public movement must not use the SOL-reserved asset field.
	splAmountIsZero := api.IsZero(publicSplAmount)
	splAssetIsSol := api.IsZero(api.Sub(publicSplAssetPubkey, SpecSolAssetID))
	api.AssertIsEqual(api.Mul(api.Sub(1, splAmountIsZero), splAssetIsSol), 0)

	// Spec rule: for each active asset, inputs plus public deposits equal
	// outputs plus public withdrawals and fees. Native SOL is asset_id = 1.
	//
	// The spec public set exposes public_spl_asset_pubkey, not a separate
	// public_spl_asset_id. This circuit compares UTXO asset_id against that
	// public field element directly; the on-chain SPP path must derive the
	// same field element from the vault mint before reconstructing
	// PublicInputHash. The exact mint/pubkey-to-field encoding is a contract
	// to freeze before production.
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

func assertSigned64Range(api frontend.API, value frontend.Variable) {
	shift := new(big.Int).Lsh(big.NewInt(1), 64)
	api.ToBinary(api.Add(value, shift), 65)
}
