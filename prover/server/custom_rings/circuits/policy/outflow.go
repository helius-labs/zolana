package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// constrainOutflow bounds every active limit row's outflow and returns whether one passes its co-sign bound.
func (p *Policy) constrainOutflow(api frontend.API, cmp comparator, t tableView, sender frontend.Variable, outputs []utxoView) frontend.Variable {
	// 1. An output to the sender inside the ring is change, every other UTXO output leaves the sender.
	leaving := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		change := api.Mul(api.IsZero(api.Sub(out.ownerPkHash, sender)), api.IsZero(api.Sub(out.ringProgramID, p.RingProgramID)))
		leaving[o] = api.Mul(out.utxo, api.Sub(1, change), out.amount)
	}
	approval := frontend.Variable(0)
	for r, row := range p.Limits {
		// 2. others sums the row asset leaving the sender, net the row asset SPP settles publicly within u64 magnitude (shared.assertBalanceConservation).
		others, net := frontend.Variable(0), frontend.Variable(0)
		for o, out := range outputs {
			others = api.Add(others, api.Mul(api.IsZero(api.Sub(out.asset, row.Asset)), leaving[o]))
		}
		for k, asset := range p.PublicAssets {
			net = api.Add(net, api.Mul(api.IsZero(api.Sub(asset, row.Asset)), p.PublicAmounts[k]))
		}
		active := t.limitActive[r]
		// 3. The outflow, others less net, is never negative, a public deposit offsets at most what leaves the sender.
		shared.AssertWhen(api, active, cmp.atMost(api, net, others))
		outflow := api.Sub(others, net)
		// 4. A nonzero cap bounds the outflow.
		shared.AssertWhen(api, api.Mul(active, gadget.IsNonZero(api, row.Cap)), cmp.atMost(api, outflow, row.Cap))
		// 5. An outflow past a nonzero co-sign bound demands the co-signer.
		cosigned := api.Mul(active, gadget.IsNonZero(api, row.CosignAbove))
		approval = api.Or(approval, api.Mul(cosigned, api.Sub(1, cmp.atMost(api, outflow, row.CosignAbove))))
	}
	return approval
}
