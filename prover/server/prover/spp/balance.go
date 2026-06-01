package spp

import (
	"math/big"

	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

// SolAsset is the asset identifier for native SOL: Sha256BE of the default
// (all-zero) Solana address, matching the Sha256BE(mint) identifier used for
// SPL assets. The identifier is derived from the mint, not a reserved constant,
// and is distinct from the compact asset_id: u64 the ciphertext layer uses.
func SolAsset() *big.Int {
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
	// UTXO amounts are unsigned 64-bit; the public amounts are signed (a deposit
	// is positive, a withdrawal negative, mapped through SignedToFe).
	for _, input := range inputs {
		assertUnsigned64Range(api, input.Utxo.AssetAmount)
	}
	for _, output := range outputs {
		assertUnsigned64Range(api, output.Utxo.AssetAmount)
	}
	assertSigned64Range(api, publicSolAmount)
	assertSigned64Range(api, publicSplAmount)

	solAsset := SolAsset()

	// SPL public movement must not use the SOL asset id.
	splAmountIsZero := api.IsZero(publicSplAmount)
	splAssetIsSol := api.IsZero(api.Sub(publicSplAssetPubkey, solAsset))
	api.AssertIsEqual(api.Mul(api.Sub(1, splAmountIsZero), splAssetIsSol), 0)

	// For each active asset, inputs plus public deposits equal outputs plus
	// public withdrawals and fees. Every input/output UTXO may be a distinct
	// asset (identified by Sha256BE(mint)); the public side touches only the
	// SOL asset and the single public_spl_asset_pubkey. Checking conservation
	// for every UTXO's asset id (not just the public two) means no asset can be
	// minted. Repeated ids only re-check the same equation, which is harmless.
	keys := make([]frontend.Variable, 0, len(inputs)+len(outputs)+2)
	for _, input := range inputs {
		keys = append(keys, input.Utxo.Asset)
	}
	for _, output := range outputs {
		keys = append(keys, output.Utxo.Asset)
	}
	keys = append(keys, solAsset, publicSplAssetPubkey)

	for _, key := range keys {
		inSum := frontend.Variable(0)
		for _, input := range inputs {
			match := api.IsZero(api.Sub(key, input.Utxo.Asset))
			inSum = api.Add(inSum, api.Mul(match, input.Utxo.AssetAmount))
		}

		outSum := frontend.Variable(0)
		for _, output := range outputs {
			match := api.IsZero(api.Sub(key, output.Utxo.Asset))
			outSum = api.Add(outSum, api.Mul(match, output.Utxo.AssetAmount))
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

// assertUnsigned64Range constrains 0 <= value < 2^64. ToBinary asserts the
// value fits in the given number of bits, which is the range check.
func assertUnsigned64Range(api frontend.API, value frontend.Variable) {
	api.ToBinary(value, 64)
}

// assertSigned64Range constrains a SignedToFe-encoded amount to
// (-2^64, 2^64): shifting by 2^64 lands it in [0, 2^65), and the 65-bit
// decomposition enforces that bound.
func assertSigned64Range(api frontend.API, value frontend.Variable) {
	shift := new(big.Int).Lsh(big.NewInt(1), 64)
	api.ToBinary(api.Add(value, shift), 65)
}
