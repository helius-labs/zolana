package spp

import (
	"fmt"
	"math/big"
)

// publicAmounts are the signed public SOL/SPL field values and the SPL asset id,
// as fed to the circuit's balance check.
type publicAmounts struct {
	sol   *big.Int
	spl   *big.Int
	asset *big.Int
}

// derivePublicAmounts validates the mode and builds the signed public amounts
// and the SPL asset id. A transfer (mode 0) must carry no public amount;
// shield/unshield set the sign (and fold the SOL relayer fee into the SOL side).
// A shield carries no relayer fee: the user pays, so the fee is always
// subtracted and a stray fee would silently skim the deposit.
func derivePublicAmounts(tx ProofTransactionRequest) (publicAmounts, error) {
	if err := validatePublicAmountMode(tx.PublicAmountMode); err != nil {
		return publicAmounts{}, err
	}
	sol := optionalU64(tx.PublicSolAmount)
	spl := optionalU64(tx.PublicSplAmount)
	if tx.PublicAmountMode == 0 && (sol != 0 || spl != 0) {
		return publicAmounts{}, fmt.Errorf("spp: transfer mode carries non-zero public amounts (sol=%d, spl=%d)", sol, spl)
	}
	if tx.PublicAmountMode == 1 && tx.RelayerFee != 0 {
		return publicAmounts{}, fmt.Errorf("spp: shield mode must not carry a relayer fee (got %d); the user pays", tx.RelayerFee)
	}
	asset := big.NewInt(0)
	if spl != 0 {
		mint, err := parseHex32(tx.PublicSplAssetPubkey)
		if err != nil {
			return publicAmounts{}, fmt.Errorf("public_spl_asset_pubkey: %w", err)
		}
		// asset = Sha256BE(mint), matching SolAsset = Sha256BE(default).
		asset = HashToFieldSize(mint[:])
	}
	return publicAmounts{
		sol:   signedSolAmount(tx.PublicAmountMode, sol, tx.RelayerFee),
		spl:   signedSplAmount(tx.PublicAmountMode, spl),
		asset: asset,
	}, nil
}

// validatePublicAmountMode rejects modes outside {0=transfer, 1=shield,
// 2=unshield}; the sign helpers are only defined for these values.
func validatePublicAmountMode(mode uint8) error {
	if mode > 2 {
		return fmt.Errorf("spp: invalid public_amount_mode %d (want 0=transfer, 1=shield, 2=unshield)", mode)
	}
	return nil
}

// signedSolAmount builds the signed public_sol_amount: ext - relayer_fee. ext
// depends on the mode (0=transfer, 1=shield, 2=unshield): +amount for shield,
// -amount for unshield, 0 for transfer. The fee is always subtracted, so a plain
// transfer pays it (-fee) and is not mistaken for an unshield. SPP rebuilds the
// same value on-chain from the u64 amount and the shield/unshield marker.
func signedSolAmount(mode uint8, amount uint64, relayerFee uint16) *big.Int {
	ext := new(big.Int).SetUint64(amount)
	switch mode {
	case 2: // unshield
		ext.Neg(ext)
	case 1: // shield
		// +amount
	default: // transfer: no public SOL movement
		ext.SetInt64(0)
	}
	ext.Sub(ext, new(big.Int).SetUint64(uint64(relayerFee)))
	return SignedToFe(ext)
}

// signedSplAmount is signedSolAmount for SPL, with no fee (the fee is paid in
// SOL): +amount for shield, -amount for unshield, 0 for transfer. A transfer
// must stay 0 — treating it as a deposit would mint SPL.
func signedSplAmount(mode uint8, amount uint64) *big.Int {
	switch mode {
	case 2: // unshield
		return SignedToFe(new(big.Int).Neg(new(big.Int).SetUint64(amount)))
	case 1: // shield
		return new(big.Int).SetUint64(amount)
	default: // transfer: no public SPL movement
		return big.NewInt(0)
	}
}
