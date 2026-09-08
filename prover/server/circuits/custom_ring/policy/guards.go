package policy

import (
	"github.com/consensys/gnark/frontend"
)

// assetLimit shares an inline match between asset coverage and per-asset
// exemptions.
type assetLimit struct {
	found     frontend.Variable
	threshold frontend.Variable
}

// outputTotals groups split outputs once for all rules checking the same owner
// or asset.
type outputTotals struct {
	byOwner         frontend.Variable
	byAsset         frontend.Variable
	byOwnerAndAsset frontend.Variable
}

// guardAmounts supplies the totals and limit selected for one rule and output.
type guardAmounts struct {
	subjectOutputTotal frontend.Variable
	ownerAssetTotal    frontend.Variable
	assetLimit         assetLimit
}

// sumOutputs makes each amount guard account for every output sharing its
// subject.
func sumOutputs(api frontend.API, outputs [NOutputs]slotView, liveOwner, liveAsset [NOutputs]frontend.Variable) [NOutputs]outputTotals {
	var totals [NOutputs]outputTotals
	for i, output := range outputs {
		totals[i] = outputTotals{byOwner: 0, byAsset: 0, byOwnerAndAsset: 0}
		for j, other := range outputs {
			// 1. Match the owner and asset of each output pair.
			sameOwner := api.IsZero(api.Sub(output.ownerPkHash, other.ownerPkHash))
			sameAsset := api.IsZero(api.Sub(output.asset, other.asset))

			// 2. Sum live amounts by owner, asset and their
			// intersection.
			ownerAmount := api.Mul(liveOwner[j], sameOwner, other.amount)
			totals[i].byOwner = api.Add(totals[i].byOwner, ownerAmount)
			totals[i].byAsset = api.Add(totals[i].byAsset, api.Mul(liveAsset[j], sameAsset, other.amount))
			totals[i].byOwnerAndAsset = api.Add(totals[i].byOwnerAndAsset, api.Mul(sameAsset, ownerAmount))
		}
	}
	return totals
}

// matchInlineAssets shares each output's inline match between asset rules and
// amount guards.
func (c *CustomRingPolicyCircuit) matchInlineAssets(api frontend.API, outputs [NOutputs]slotView, inlineEnabled [NInlineAssets]frontend.Variable) [NOutputs]assetLimit {
	var limits [NOutputs]assetLimit
	for i, output := range outputs {
		var matches [NInlineAssets]frontend.Variable
		threshold := frontend.Variable(0)
		// 1. Match the output against committed inline assets and
		// collect their limits.
		for j, asset := range c.InlineAssets {
			matches[j] = api.Mul(inlineEnabled[j], api.IsZero(api.Sub(asset, output.asset)))
			threshold = api.Add(threshold, api.Mul(matches[j], c.InlineLimits[j]))
		}

		// 2. Accept inline coverage when any configured asset matches.
		limits[i] = assetLimit{found: anyOf(api, matches[:]), threshold: threshold}
	}
	return limits
}

// amountExemption permits missing coverage only within the rule's grouped
// amount limit.
func (w RuleWires) amountExemption(api frontend.API, amounts guardAmounts) frontend.Variable {
	// 1. Compare the subject total with the scalar threshold.
	scalar := api.Mul(
		api.IsZero(api.Sub(w.GuardTag, GuardAboveAmount)),
		atMostAggregated(api, amounts.subjectOutputTotal, w.Threshold),
	)

	// 2. Compare the owner-and-asset total with its configured limit.
	perAsset := api.Mul(
		api.IsZero(api.Sub(w.GuardTag, GuardAboveAmountByAsset)),
		amounts.assetLimit.found,
		atMostAggregated(api, amounts.ownerAssetTotal, amounts.assetLimit.threshold),
	)

	// 3. Accept an exemption only from the selected guard.
	return api.Or(scalar, perAsset)
}

// atMostAggregated compares a bounded output total with its threshold.
// Both operands must be nonnegative and below amountSumOffset.
func atMostAggregated(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	return api.ToBinary(api.Add(api.Sub(threshold, total), amountSumOffset), amountSumBits+1)[amountSumBits]
}
