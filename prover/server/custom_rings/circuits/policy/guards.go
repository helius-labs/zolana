// Checks amount exemptions against totals grouped by owner and asset,
// including transfers split across several outputs.

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
	subjectOutputTotal    frontend.Variable
	ownerAssetOutputTotal frontend.Variable
	assetLimit            assetLimit
}

// sumOutputs makes each amount guard account for every output sharing its
// subject.
func sumOutputs(api frontend.API, outputs [NOutputs]utxoView, liveOwner, liveAsset [NOutputs]frontend.Variable) [NOutputs]outputTotals {
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

// resolveOutputAssetLimits shares inline membership and limits across rules.
func (c *CustomRingPolicyCircuit) resolveOutputAssetLimits(api frontend.API, outputs [NOutputs]utxoView, inlineEnabled [NInlineAssets]frontend.Variable) [NOutputs]assetLimit {
	var limits [NOutputs]assetLimit
	for i, output := range outputs {
		limits[i] = c.matchInlineAssets(api, output.asset, inlineEnabled)
	}
	return limits
}

// matchInlineAssets excludes inactive inline slots from membership and limits.
func (c *CustomRingPolicyCircuit) matchInlineAssets(api frontend.API, outputAsset frontend.Variable, inlineEnabled [NInlineAssets]frontend.Variable) assetLimit {
	// 1. Match the output asset and collect its configured limits.
	var matches [NInlineAssets]frontend.Variable
	threshold := frontend.Variable(0)
	for i, asset := range c.InlineAssets {
		matches[i] = api.Mul(inlineEnabled[i], api.IsZero(api.Sub(asset, outputAsset)))
		threshold = api.Add(threshold, api.Mul(matches[i], c.InlineLimits[i]))
	}

	// 2. Accept inline coverage when any configured asset matches.
	return assetLimit{found: anyOf(api, matches[:]), threshold: threshold}
}

// amountExemption permits missing coverage only within the rule's grouped
// amount limit.
func (w RuleWires) amountExemption(api frontend.API, amounts guardAmounts) frontend.Variable {
	// 1. Compare the subject total with the scalar threshold.
	scalar := api.Mul(
		api.IsZero(api.Sub(w.GuardTag, GuardAboveAmount)),
		outputTotalAtMost(api, amounts.subjectOutputTotal, w.Threshold),
	)

	// 2. Compare the owner-and-asset total with its configured limit.
	perAsset := api.Mul(
		api.IsZero(api.Sub(w.GuardTag, GuardAboveAmountByAsset)),
		amounts.assetLimit.found,
		outputTotalAtMost(api, amounts.ownerAssetOutputTotal, amounts.assetLimit.threshold),
	)

	// 3. Accept an exemption only from the selected guard.
	return api.Or(scalar, perAsset)
}

// outputTotalAtMost compares a bounded output total with its threshold.
// Both operands must be nonnegative and below amountSumOffset.
func outputTotalAtMost(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	return api.ToBinary(api.Add(api.Sub(threshold, total), amountSumOffset), amountSumBits+1)[amountSumBits]
}
