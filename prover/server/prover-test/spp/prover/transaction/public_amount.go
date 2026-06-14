package transaction

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
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

// derivePublicAmounts computes the signed public amounts the balance circuit
// consumes (`inSum + publicAmount == outSum` per asset). Each is the net
// external flow as a field element, Tornado-Nova style: deposit is positive,
// withdrawal is negative and wrapped mod p by SignedToField (so `-x` becomes
// `p - x`), and the relayer fee is folded into the withdrawal — but only on the
// SOL leg, since fees are paid in SOL.
func derivePublicAmounts(tx ProofTransactionRequest) (publicAmounts, error) {
	sol := u64OrZero(tx.PublicSolAmount)
	spl := u64OrZero(tx.PublicSplAmount)
	// Validate the per-mode invariants with one switch on the mode (mirrors the
	// switch in signedSolAmount/signedSplAmount), so the invalid-mode guard and
	// the mode-specific checks live in one place.
	switch tx.PublicAmountMode {
	case publicAmountTransfer:
		if sol != 0 || spl != 0 || tx.RelayerFee != 0 {
			return publicAmounts{}, fmt.Errorf("spp: transfer mode carries public settlement")
		}
	case publicAmountShield:
		if tx.RelayerFee != 0 {
			return publicAmounts{}, fmt.Errorf("spp: shield mode carries relayer fee")
		}
	case publicAmountUnshield:
		// Withdraws may carry a relayer fee and public settlement.
	default:
		return publicAmounts{}, fmt.Errorf("spp: invalid public_amount_mode %d", tx.PublicAmountMode)
	}

	asset := big.NewInt(0)
	if spl != 0 {
		mint, err := parse.Hex32(tx.PublicSplAssetPubkey)
		if err != nil {
			return publicAmounts{}, fmt.Errorf("public_spl_asset_pubkey: %w", err)
		}
		asset, err = protocol.SolanaPkField(mint)
		if err != nil {
			return publicAmounts{}, fmt.Errorf("public_spl_asset_pubkey: %w", err)
		}
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
		return big.NewInt(0)
	case publicAmountShield:
		return value
	case publicAmountUnshield:
		value.Add(value, new(big.Int).SetUint64(uint64(relayerFee)))
		value.Neg(value)
	}
	return protocol.SignedToField(value)
}

func signedSplAmount(mode uint8, amount uint64) *big.Int {
	value := new(big.Int).SetUint64(amount)
	switch mode {
	case publicAmountShield:
		return value
	case publicAmountUnshield:
		return protocol.SignedToField(value.Neg(value))
	default:
		return big.NewInt(0)
	}
}
