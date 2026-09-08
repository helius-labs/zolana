package policy

import (
	"github.com/consensys/gnark/frontend"
)

type assetLimit struct {
	found     frontend.Variable
	threshold frontend.Variable
}

type outputTotals struct {
	byOwner         frontend.Variable
	byAsset         frontend.Variable
	byOwnerAndAsset frontend.Variable
}

type guardAmounts struct {
	subjectTotal    frontend.Variable
	ownerAssetTotal frontend.Variable
	assetLimit      assetLimit
}

func sumOutputs(api frontend.API, outputs [NOut]slotView, liveOwner, liveAsset [NOut]frontend.Variable) [NOut]outputTotals {
	var totals [NOut]outputTotals
	for i, output := range outputs {
		totals[i] = outputTotals{byOwner: 0, byAsset: 0, byOwnerAndAsset: 0}
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

func (c *CustomRingPolicyCircuit) matchInlineAssets(api frontend.API, outputs [NOut]slotView, inlineEnabled [NInlineAssets]frontend.Variable) [NOut]assetLimit {
	var limits [NOut]assetLimit
	for i, output := range outputs {
		var matches [NInlineAssets]frontend.Variable
		threshold := frontend.Variable(0)
		for j, asset := range c.InlineAssets {
			matches[j] = api.Mul(inlineEnabled[j], api.IsZero(api.Sub(asset, output.asset)))
			threshold = api.Add(threshold, api.Mul(matches[j], c.InlineLimits[j]))
		}
		limits[i] = assetLimit{found: anyOf(api, matches[:]), threshold: threshold}
	}
	return limits
}

func (w RuleWires) amountExemption(api frontend.API, amounts guardAmounts) frontend.Variable {
	scalar := api.Mul(
		api.IsZero(api.Sub(w.GuardTag, GuardAboveAmount)),
		sumAtMost(api, amounts.subjectTotal, w.Threshold),
	)
	perAsset := api.Mul(
		api.IsZero(api.Sub(w.GuardTag, GuardAboveAmountByAsset)),
		amounts.assetLimit.found,
		sumAtMost(api, amounts.ownerAssetTotal, amounts.assetLimit.threshold),
	)
	return api.Or(scalar, perAsset)
}

// Both operands must fit below amountSumOffset.
func sumAtMost(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	return api.ToBinary(api.Add(api.Sub(threshold, total), amountSumOffset), amountSumBits+1)[amountSumBits]
}
