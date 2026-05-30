package spp

import (
	"math/big"

	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

// SolAssetID is the asset identifier for native SOL: Sha256BE of the default
// (all-zero) Solana address, matching the Sha256BE(mint) identifier used for
// SPL assets. The asset_id is derived from the mint, not a reserved constant.
func SolAssetID() *big.Int {
	return HashToFieldSize(make([]byte, 32))
}

// SignedToFe maps signed public amounts into their canonical BN254 Fr
// representative. Positive values pass through; negative values become
// modulus - |value|.
func SignedToFe(value *big.Int) *big.Int {
	return new(big.Int).Mod(value, poseidon.Modulus)
}

func assertBalanceConservation(
	api frontend.API,
	inputs []Input,
	outputs []Output,
	publicSolAmount frontend.Variable,
	publicSplAmount frontend.Variable,
	publicSplAssetPubkey frontend.Variable,
) {
	assertSigned64Range(api, publicSolAmount)
	assertSigned64Range(api, publicSplAmount)

	solAssetID := SolAssetID()

	// SPL public movement must not use the SOL asset id.
	splAmountIsZero := api.IsZero(publicSplAmount)
	splAssetIsSol := api.IsZero(api.Sub(publicSplAssetPubkey, solAssetID))
	api.AssertIsEqual(api.Mul(api.Sub(1, splAmountIsZero), splAssetIsSol), 0)

	// For each active asset, inputs plus public deposits equal outputs plus
	// public withdrawals and fees. Every input/output UTXO may be a distinct
	// asset (identified by Sha256BE(mint)); the public side touches only the
	// SOL asset and the single public_spl_asset_pubkey. Iterating over every
	// UTXO's asset id checks conservation for all assets, not just the public
	// two, so no asset can be minted.
	keys := make([]frontend.Variable, 0, len(inputs)+len(outputs)+2)
	for _, input := range inputs {
		api.ToBinary(input.Utxo.AssetAmount, 64)
		keys = append(keys, input.Utxo.AssetID)
	}
	for _, output := range outputs {
		api.ToBinary(output.Utxo.AssetAmount, 64)
		keys = append(keys, output.Utxo.AssetID)
	}
	keys = append(keys, solAssetID, publicSplAssetPubkey)

	for _, key := range keys {
		inSum := frontend.Variable(0)
		for _, input := range inputs {
			match := api.IsZero(api.Sub(key, input.Utxo.AssetID))
			inSum = api.Add(inSum, api.Mul(match, input.Utxo.AssetAmount))
		}

		outSum := frontend.Variable(0)
		for _, output := range outputs {
			match := api.IsZero(api.Sub(key, output.Utxo.AssetID))
			outSum = api.Add(outSum, api.Mul(match, output.Utxo.AssetAmount))
		}

		solMatch := api.IsZero(api.Sub(key, solAssetID))
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
