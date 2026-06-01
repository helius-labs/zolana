package spp

import (
	"math/big"

	"light/light-prover/prover/poseidon"

	"github.com/consensys/gnark/frontend"
)

// SolAsset is the asset id for native SOL: Sha256BE of the default (all-zero)
// Solana address, derived from the mint like SPL assets (Sha256BE(mint)). It is
// not the compact asset_id: u64 used by the ciphertext layer.
func SolAsset() *big.Int {
	return HashToFieldSize(make([]byte, 32))
}

// SignedToFe encodes a signed amount as a BN254 field element: positive values
// stay as-is, negative values become modulus - |value|.
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
	assertSignedAmountRange(api, publicSolAmount)
	assertSignedAmountRange(api, publicSplAmount)

	solAsset := SolAsset()

	// SPL public movement must not use the SOL asset id.
	splAmountIsZero := api.IsZero(publicSplAmount)
	splAssetIsSol := api.IsZero(api.Sub(publicSplAssetPubkey, solAsset))
	api.AssertIsEqual(api.Mul(api.Sub(1, splAmountIsZero), splAssetIsSol), 0)

	// Check balance per asset: inputs + public deposits == outputs + public
	// withdrawals + fees. Each UTXO may hold a different asset (id =
	// Sha256BE(mint)); the public side touches only SOL and the one
	// public_spl_asset_pubkey. Checking every UTXO's asset (not just those two)
	// is what stops any asset from being minted. A repeated id just re-checks
	// the same equation, which is safe.
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

// assertSignedAmountRange keeps a public amount in the range the program can
// build from u64 instruction amounts: -2^64 <= amount < 2^64. Without this, a
// bad witness could use an arbitrary field value that only balances modulo
// BN254.
func assertSignedAmountRange(api frontend.API, value frontend.Variable) {
	shift := new(big.Int).Lsh(big.NewInt(1), 64)
	api.ToBinary(api.Add(value, shift), 65)
}
