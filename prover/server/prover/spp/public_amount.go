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

// derivePublicAmounts validates the mode and derives the signed public amounts
// and SPL asset id in one place. A transfer (mode 0) must carry no public
// amount; shield/unshield set the sign (with the SOL relayer fee folded in).
func derivePublicAmounts(tx ProofTransactionRequest) (publicAmounts, error) {
	if err := validatePublicAmountMode(tx.PublicAmountMode); err != nil {
		return publicAmounts{}, err
	}
	sol := optionalU64(tx.PublicSolAmount)
	spl := optionalU64(tx.PublicSplAmount)
	if tx.PublicAmountMode == 0 && (sol != 0 || spl != 0) {
		return publicAmounts{}, fmt.Errorf("spp: transfer mode carries non-zero public amounts (sol=%d, spl=%d)", sol, spl)
	}
	asset := big.NewInt(0)
	if spl != 0 {
		mint, err := parseHex32(tx.PublicSplAssetPubkey)
		if err != nil {
			return publicAmounts{}, fmt.Errorf("public_spl_asset_pubkey: %w", err)
		}
		// asset_id = Sha256BE(mint), matching SolAssetID = Sha256BE(default).
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

// signedSolAmount produces the signed `public_sol_amount` field value, the
// tornado-nova convention: ext - relayer_fee, where ext is +amount to shield,
// -amount to unshield, 0 to transfer. The relayer fee is always subtracted, so
// a plain transfer pays it (-fee) without being encoded as an unshield. SPP
// builds the same value on-chain from the u64 amount and the shield/unshield
// marker. mode: 0 = transfer, 1 = shield, 2 = unshield.
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

// signedSplAmount mirrors signedSolAmount for SPL (no relayer fee, which is paid
// in SOL): shield adds +amount, unshield subtracts amount, and a transfer moves
// nothing. A transfer must NOT be treated as a deposit, or it would mint SPL.
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
