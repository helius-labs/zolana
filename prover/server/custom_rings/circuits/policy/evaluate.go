package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// constrainRules requires a matching list fact or an amount exemption for every live subject of an enabled rule.
func (c *CustomRingPolicyCircuit) constrainRules(api frontend.API, tx transaction, facts [NListFacts]listFact, checked checkedPolicy) {
	var sameOwner, sameAsset [NListFacts][NOutputs]frontend.Variable
	var sameSender [NListFacts][NInputs]frontend.Variable
	for f, fact := range facts {
		for o, output := range tx.outputs {
			sameOwner[f][o] = api.IsZero(api.Sub(fact.member, output.ownerPkHash))
			sameAsset[f][o] = api.IsZero(api.Sub(fact.member, output.asset))
		}
		for i, input := range tx.inputs {
			sameSender[f][i] = api.IsZero(api.Sub(fact.member, input.ownerPkHash))
		}
	}
	// Zero subjects create no obligation.
	var liveOwner, liveAsset [NOutputs]frontend.Variable
	var limits [NOutputs]assetLimit
	for o, output := range tx.outputs {
		liveOwner[o] = api.Mul(output.live, base.NonZero(api, output.ownerPkHash))
		liveAsset[o] = api.Mul(output.live, base.NonZero(api, output.asset))
		limits[o] = c.matchInlineAssets(api, output.asset, checked.inline.Active)
	}
	totals := sumOutputs(api, tx.outputs, liveOwner, liveAsset)

	for r, rule := range checked.rules {
		matches := rule.matchListAndMode(api, facts)
		onOutput := api.Mul(checked.ruleEnabled[r], api.Add(rule.onOwner, rule.onAsset))
		for o := range tx.outputs {
			var hits [NListFacts]frontend.Variable
			for f := range facts {
				hits[f] = api.Mul(matches[f], api.Select(rule.onAsset, sameAsset[f][o], sameOwner[f][o]))
			}
			enabled := api.Mul(onOutput, api.Select(rule.onAsset, liveAsset[o], liveOwner[o]))
			satisfied := api.Select(rule.inline, limits[o].found, base.AnyOf(api, hits[:]...))
			// Per-asset limits apply even when the list condition holds.
			shared.AssertWhen(api, api.Mul(enabled, rule.assetGuard), limits[o].found)
			subjectTotal := api.Select(rule.onAsset, totals[o].byAsset, totals[o].byOwner)
			shared.AssertWhen(api, enabled, api.Or(satisfied, rule.amountExemption(api, subjectTotal, totals[o].byOwnerAndAsset, limits[o])))
		}
		onInput := api.Mul(checked.ruleEnabled[r], rule.onSender)
		for i, input := range tx.inputs {
			var hits [NListFacts]frontend.Variable
			for f := range facts {
				hits[f] = api.Mul(matches[f], sameSender[f][i])
			}
			shared.AssertWhen(api, api.Mul(onInput, input.live, base.NonZero(api, input.ownerPkHash)), base.AnyOf(api, hits[:]...))
		}
	}
}
