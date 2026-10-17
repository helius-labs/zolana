package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// assetLimit is the inline match of one output's asset and its configured limit.
type assetLimit struct {
	found, threshold frontend.Variable
}

// outputTotals sum the live amounts that share an output's owner, asset, or both.
type outputTotals struct {
	byOwner, byAsset, byOwnerAndAsset frontend.Variable
}

func sumOutputs(api frontend.API, outputs []utxoView, liveOwner, liveAsset []frontend.Variable) []outputTotals {
	totals := make([]outputTotals, len(outputs))
	for i, output := range outputs {
		totals[i] = outputTotals{0, 0, 0}
		for j, other := range outputs {
			sameOwner := api.IsZero(api.Sub(output.ownerPkHash, other.ownerPkHash))
			sameAsset := api.IsZero(api.Sub(output.asset, other.asset))
			ownerAmount := api.Mul(liveOwner[j], sameOwner, other.amount)
			totals[i].byOwner = api.Add(totals[i].byOwner, ownerAmount)
			totals[i].byAsset = api.Add(totals[i].byAsset, api.Mul(liveAsset[j], sameAsset, other.amount))
			totals[i].byOwnerAndAsset = api.Add(totals[i].byOwnerAndAsset, api.Mul(sameAsset, ownerAmount))
		}
	}
	return totals
}

func (c *CustomRingPolicyCircuit) matchInlineAssets(api frontend.API, asset frontend.Variable, enabled []frontend.Variable) assetLimit {
	matches := make([]frontend.Variable, NAmountGuards)
	threshold := frontend.Variable(0)
	for i, inline := range c.InlineAssets {
		matches[i] = api.Mul(enabled[i], api.IsZero(api.Sub(inline, asset)))
		threshold = api.Add(threshold, api.Mul(matches[i], c.InlineLimits[i]))
	}
	return assetLimit{found: base.AnyOf(api, matches...), threshold: threshold}
}

// amountExemption waives coverage within the selected guard's grouped amount limit.
func (r ruleFields) amountExemption(api frontend.API, subjectTotal, ownerAssetTotal frontend.Variable, limit assetLimit) frontend.Variable {
	return r.amountExemptionWith(api, subjectTotal, ownerAssetTotal, limit, outputTotalAtMost)
}

func (r ruleFields) amountExemptionWith(api frontend.API, subjectTotal, ownerAssetTotal frontend.Variable, limit assetLimit, atMost func(frontend.API, frontend.Variable, frontend.Variable) frontend.Variable) frontend.Variable {
	scalar := api.Mul(r.scalarGuard, atMost(api, subjectTotal, r.threshold))
	perAsset := api.Mul(r.assetGuard, limit.found, atMost(api, ownerAssetTotal, limit.threshold))
	return api.Or(scalar, perAsset)
}

// outputTotalAtMost needs both operands nonnegative and below amountSumOffset.
func outputTotalAtMost(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	return api.ToBinary(api.Add(api.Sub(threshold, total), amountSumOffset), amountSumBits+1)[amountSumBits]
}
