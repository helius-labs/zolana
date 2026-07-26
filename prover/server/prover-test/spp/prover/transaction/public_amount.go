package transaction

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

// MaxEncodedPublicLegs is the wire-format ceiling: external_data_hash encodes
// the ordered public-leg count in one byte. Solana transaction size and account
// limits impose a much lower practical bound for real transactions.
const MaxEncodedPublicLegs = 1<<8 - 1

type publicSlots struct {
	assets  [protocol.NPublicSlots]*big.Int
	amounts [protocol.NPublicSlots]*big.Int
}

type aggregatedPublicAsset struct {
	asset  *big.Int
	amount *big.Int
}

func derivePublicSlots(tx ProofTransactionRequest) (publicSlots, error) {
	if len(tx.PublicLegs) > MaxEncodedPublicLegs {
		return publicSlots{}, fmt.Errorf(
			"spp: public_legs length %d exceeds u8 encoding maximum %d",
			len(tx.PublicLegs),
			MaxEncodedPublicLegs,
		)
	}

	aggregates := make([]*aggregatedPublicAsset, 0, len(tx.PublicLegs))
	for position, leg := range tx.PublicLegs {
		if leg.Amount == 0 {
			return publicSlots{}, fmt.Errorf("spp: public_legs[%d].amount must be nonzero", position)
		}
		asset, err := publicLegAsset(leg, position)
		if err != nil {
			return publicSlots{}, err
		}
		found := false
		for _, aggregate := range aggregates {
			if aggregate.asset.Cmp(asset) == 0 {
				aggregate.amount.Add(aggregate.amount, signedPublicLegAmount(leg))
				found = true
				break
			}
		}
		if !found {
			aggregates = append(aggregates, &aggregatedPublicAsset{
				asset:  asset,
				amount: signedPublicLegAmount(leg),
			})
		}
	}

	activeCount := 0
	for _, aggregate := range aggregates {
		if aggregate.amount.Sign() != 0 {
			activeCount++
		}
	}
	if activeCount > protocol.NPublicSlots {
		return publicSlots{}, fmt.Errorf(
			"spp: public legs aggregate to more than %d distinct nonzero assets",
			protocol.NPublicSlots,
		)
	}
	assets := make([]*big.Int, 0, protocol.NPublicSlots)
	amounts := make([]*big.Int, 0, protocol.NPublicSlots)
	for _, aggregate := range aggregates {
		if aggregate.amount.Sign() == 0 {
			continue
		}
		if new(big.Int).Abs(new(big.Int).Set(aggregate.amount)).BitLen() > 64 {
			return publicSlots{}, fmt.Errorf("spp: public leg aggregate magnitude exceeds u64")
		}
		assets = append(assets, aggregate.asset)
		amounts = append(amounts, protocol.SignedToField(aggregate.amount))
	}
	for len(assets) < protocol.NPublicSlots {
		assets = append(assets, big.NewInt(0))
		amounts = append(amounts, big.NewInt(0))
	}
	var slots publicSlots
	copy(slots.assets[:], assets)
	copy(slots.amounts[:], amounts)
	return slots, nil
}

func signedPublicLegAmount(leg PublicLegRequest) *big.Int {
	amount := new(big.Int).SetUint64(leg.Amount)
	if !leg.IsDeposit {
		amount.Neg(amount)
	}
	return amount
}

func publicLegAsset(leg PublicLegRequest, index int) (*big.Int, error) {
	if !leg.IsSpl {
		if leg.Asset != "" {
			return nil, fmt.Errorf("public_legs[%d].asset must be empty for SOL", index)
		}
		return protocol.SolAsset(), nil
	}
	mint, err := parse.Hex32(leg.Asset)
	if err != nil {
		return nil, fmt.Errorf("public_legs[%d].asset: %w", index, err)
	}
	asset, err := protocol.SolanaPkField(mint)
	if err != nil {
		return nil, fmt.Errorf("public_legs[%d].asset: %w", index, err)
	}
	return asset, nil
}
