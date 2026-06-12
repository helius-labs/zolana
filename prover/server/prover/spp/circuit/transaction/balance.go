package transaction

import (
	"math/big"

	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark/frontend"
)

const (
	amountBits       = 64
	signedAmountBits = amountBits + 1
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

	solAsset := protocol.SolAsset()

	// SPL public movement cannot target the SOL asset.
	splAmountIsZero := api.IsZero(publicSplAmount)
	splAssetIsSol := api.IsZero(api.Sub(publicSplAssetPubkey, solAsset))
	api.AssertIsEqual(api.Mul(api.Sub(1, splAmountIsZero), splAssetIsSol), 0)

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

func rangeCheck64(api frontend.API, value frontend.Variable) {
	api.ToBinary(value, amountBits)
}

func rangeCheckSigned64(api frontend.API, value frontend.Variable) {
	api.ToBinary(api.Add(value, signedAmountOffset()), signedAmountBits)
}

func signedAmountOffset() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), amountBits)
}
