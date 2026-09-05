package transaction

import (
	"fmt"
	"math/big"

	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"
)

// MaxInterfaceTransfers matches the program's validation bound. The wire count
// is one byte, but accepting shapes the program always rejects would let the Go
// prover produce unusable proofs.
const MaxInterfaceTransfers = 32

type publicSlots struct {
	assets  [protocol.NPublicSlots]*big.Int
	amounts [protocol.NPublicSlots]*big.Int
}

type aggregatedPublicAsset struct {
	asset  *big.Int
	amount *big.Int
}

func derivePublicSlots(tx ProofTransactionRequest) (publicSlots, error) {
	if len(tx.InterfaceTransfers) > MaxInterfaceTransfers {
		return publicSlots{}, fmt.Errorf(
			"spp: interface_transfers length %d exceeds protocol maximum %d",
			len(tx.InterfaceTransfers),
			MaxInterfaceTransfers,
		)
	}

	aggregates := make([]*aggregatedPublicAsset, 0, len(tx.InterfaceTransfers))
	for position, transfer := range tx.InterfaceTransfers {
		if transfer.Amount == 0 {
			return publicSlots{}, fmt.Errorf("spp: interface_transfers[%d].amount must be nonzero", position)
		}
		asset, err := interfaceTransferAsset(transfer, position)
		if err != nil {
			return publicSlots{}, err
		}
		found := false
		for _, aggregate := range aggregates {
			if aggregate.asset.Cmp(asset) == 0 {
				aggregate.amount.Add(aggregate.amount, signedInterfaceTransferAmount(transfer))
				found = true
				break
			}
		}
		if !found {
			aggregates = append(aggregates, &aggregatedPublicAsset{
				asset:  asset,
				amount: signedInterfaceTransferAmount(transfer),
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
			"spp: interface transfers aggregate to more than %d distinct nonzero assets",
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
			return publicSlots{}, fmt.Errorf("spp: interface transfer aggregate magnitude exceeds u64")
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

func signedInterfaceTransferAmount(transfer InterfaceTransferRequest) *big.Int {
	amount := new(big.Int).SetUint64(transfer.Amount)
	if !transfer.IsDeposit {
		amount.Neg(amount)
	}
	return amount
}

func interfaceTransferAsset(transfer InterfaceTransferRequest, index int) (*big.Int, error) {
	if !transfer.IsSpl {
		if transfer.Asset != "" {
			return nil, fmt.Errorf("interface_transfers[%d].asset must be empty for SOL", index)
		}
		return protocol.SolAsset(), nil
	}
	mint, err := parse.Hex32(transfer.Asset)
	if err != nil {
		return nil, fmt.Errorf("interface_transfers[%d].asset: %w", index, err)
	}
	asset, err := protocol.SolanaPkField(mint)
	if err != nil {
		return nil, fmt.Errorf("interface_transfers[%d].asset: %w", index, err)
	}
	return asset, nil
}
