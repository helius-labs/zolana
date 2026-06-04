package transaction

import (
	"fmt"
	"math/big"

	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"
)

const (
	publicAmountTransfer = 0
	publicAmountShield   = 1
	publicAmountUnshield = 2
)

type publicAmounts struct {
	sol   *big.Int
	spl   *big.Int
	asset *big.Int
}

func derivePublicAmounts(tx ProofTransactionRequest) (publicAmounts, error) {
	if tx.PublicAmountMode > publicAmountUnshield {
		return publicAmounts{}, fmt.Errorf("spp: invalid public_amount_mode %d", tx.PublicAmountMode)
	}

	sol := u64OrZero(tx.PublicSolAmount)
	spl := u64OrZero(tx.PublicSplAmount)
	if tx.PublicAmountMode == publicAmountTransfer && (sol != 0 || spl != 0) {
		return publicAmounts{}, fmt.Errorf("spp: transfer mode carries public amounts")
	}
	if tx.PublicAmountMode == publicAmountShield && tx.RelayerFee != 0 {
		return publicAmounts{}, fmt.Errorf("spp: shield mode carries relayer fee")
	}

	asset := big.NewInt(0)
	if spl != 0 {
		mint, err := parse.Hex32(tx.PublicSplAssetPubkey)
		if err != nil {
			return publicAmounts{}, fmt.Errorf("public_spl_asset_pubkey: %w", err)
		}
		asset = model.HashToFieldSize(mint[:])
	}

	return publicAmounts{
		sol:   signedSolAmount(tx.PublicAmountMode, sol, tx.RelayerFee),
		spl:   signedSplAmount(tx.PublicAmountMode, spl),
		asset: asset,
	}, nil
}

func signedSolAmount(mode uint8, amount uint64, relayerFee uint16) *big.Int {
	value := new(big.Int).SetUint64(amount)
	switch mode {
	case publicAmountTransfer:
		value.SetInt64(0)
	case publicAmountUnshield:
		value.Neg(value)
	}
	value.Sub(value, new(big.Int).SetUint64(uint64(relayerFee)))
	return model.SignedToFe(value)
}

func signedSplAmount(mode uint8, amount uint64) *big.Int {
	value := new(big.Int).SetUint64(amount)
	switch mode {
	case publicAmountShield:
		return value
	case publicAmountUnshield:
		return model.SignedToFe(value.Neg(value))
	default:
		return big.NewInt(0)
	}
}
