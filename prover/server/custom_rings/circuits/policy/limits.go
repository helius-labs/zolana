package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// OutflowLimitWires caps one asset's outflow per transfer and sets its co-sign threshold, zero turns either off.
type OutflowLimitWires struct {
	Asset       frontend.Variable
	Cap         frontend.Variable
	CosignAbove frontend.Variable
}

// Rows hold distinct assets with at least one bound, padding stays zero.
func (c *CustomRingPolicyCircuit) checkLimitTable(api frontend.API, rc frontend.Rangechecker) base.Count {
	rows := base.SelectCount(api, c.LimitCount, 0, NOutflowLimits+1)
	for i, row := range c.Limits {
		rc.Check(row.Cap, amountBits)
		rc.Check(row.CosignAbove, amountBits)
		shared.AssertWhen(api, rows.Active[i], base.NonZero(api, row.Asset))
		shared.AssertWhen(api, rows.Active[i], base.NonZero(api, api.Add(row.Cap, row.CosignAbove)))
		padding := api.Sub(1, rows.Active[i])
		for _, value := range []frontend.Variable{row.Asset, row.Cap, row.CosignAbove} {
			api.AssertIsEqual(api.Mul(padding, value), 0)
		}
		for j, other := range c.Limits[:i] {
			shared.AssertWhen(api, api.Mul(rows.Active[i], rows.Active[j]), base.NonZero(api, api.Sub(row.Asset, other.Asset)))
		}
	}
	return rows
}

// Outflow counts every UTXO input of the single sender, less change returned to the sender inside the ring.
func (c *CustomRingPolicyCircuit) constrainLimits(api frontend.API, rows base.Count, tx transaction) {
	rowsEnabled := api.Sub(1, rows.OneHot[0])
	shared.AssertWhen(api, rowsEnabled, tx.inputs[0].utxo)
	sender := tx.inputs[0].ownerPkHash
	for _, input := range tx.inputs[1:] {
		shared.AssertWhen(api, api.Mul(rowsEnabled, input.utxo), api.IsZero(api.Sub(input.ownerPkHash, sender)))
	}

	approval := frontend.Variable(0)
	for r, row := range c.Limits {
		inflow, change := frontend.Variable(0), frontend.Variable(0)
		for _, input := range tx.inputs {
			inflow = api.Add(inflow, api.Mul(input.utxo, api.IsZero(api.Sub(input.asset, row.Asset)), input.amount))
		}
		for _, output := range tx.outputs {
			toSender := api.Mul(api.IsZero(api.Sub(output.ownerPkHash, sender)), api.IsZero(api.Sub(output.ringProgramID, c.RingID)))
			change = api.Add(change, api.Mul(output.utxo, api.IsZero(api.Sub(output.asset, row.Asset)), toSender, output.amount))
		}
		shared.AssertWhen(api, rows.Active[r], c.amountAtMost(api, change, inflow))
		outflow := api.Sub(inflow, change)
		capped := api.Mul(rows.Active[r], base.NonZero(api, row.Cap))
		shared.AssertWhen(api, capped, c.amountAtMost(api, outflow, row.Cap))
		cosigned := api.Mul(rows.Active[r], base.NonZero(api, row.CosignAbove))
		approval = api.Or(approval, api.Mul(cosigned, api.Sub(1, c.amountAtMost(api, outflow, row.CosignAbove))))
	}
	api.AssertIsBoolean(c.ApprovalRequired)
	api.AssertIsEqual(c.ApprovalRequired, approval)
}
