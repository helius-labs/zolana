package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// constrainRules requires every live subject of an enabled rule to satisfy it on its lists or an amount exemption.
func (c *CustomRingPolicyCircuit) constrainRules(api frontend.API, tx transaction, subjects [NSubjects]subjectView, checked checkedPolicy) {
	// Zero subjects create no obligation.
	var liveOwner, liveAsset [NOutputs]frontend.Variable
	var limits [NOutputs]assetLimit
	for o, output := range tx.outputs {
		liveOwner[o] = api.Mul(output.utxo, base.NonZero(api, output.ownerPkHash))
		liveAsset[o] = api.Mul(output.utxo, base.NonZero(api, output.asset))
		limits[o] = c.matchInlineAssets(api, output.asset, checked.inline.Active)
	}
	totals := sumOutputs(api, tx.outputs, liveOwner, liveAsset)

	for r, rule := range checked.rules {
		for i, left := range tx.outputs {
			for _, right := range tx.outputs[:i] {
				enabled := api.Mul(checked.ruleEnabled[r], rule.onOwner, rule.scalarGuard, left.utxo, right.utxo)
				api.AssertIsEqual(api.Mul(enabled, api.Sub(left.asset, right.asset)), 0)
			}
		}
		onOutput := api.Mul(checked.ruleEnabled[r], api.Add(rule.onOwner, rule.onAsset))
		for o := range tx.outputs {
			enabled := api.Mul(onOutput, api.Select(rule.onAsset, liveAsset[o], liveOwner[o]))
			satisfied := api.Select(rule.onAsset, rule.satisfiedBy(api, subjects[NInputs+NOutputs+o]), rule.satisfiedBy(api, subjects[NInputs+o]))
			// Per-asset limits apply even when the list condition holds.
			shared.AssertWhen(api, api.Mul(enabled, rule.assetGuard), limits[o].found)
			subjectTotal := api.Select(rule.onAsset, totals[o].byAsset, totals[o].byOwner)
			shared.AssertWhen(api, enabled, api.Or(satisfied, rule.amountExemption(api, subjectTotal, totals[o].byOwnerAndAsset, limits[o])))
		}
		onInput := api.Mul(checked.ruleEnabled[r], rule.onSender)
		for i, input := range tx.inputs {
			enabled := api.Mul(onInput, input.utxo, base.NonZero(api, input.ownerPkHash))
			shared.AssertWhen(api, enabled, rule.satisfiedBy(api, subjects[i]))
		}
	}
}

// satisfiedBy holds when the subject is on a primary list in the rule's mode, or off every alternative list.
func (r ruleFields) satisfiedBy(api frontend.API, subject subjectView) frontend.Variable {
	onPrimary := listMaskHits(api, r.listBits, subject.onList)
	onAlternative := listMaskHits(api, r.altBits, subject.onList)
	primary := api.Select(r.present, onPrimary, api.Sub(1, onPrimary))
	return api.Or(primary, api.Mul(r.hasAlternative, api.Sub(1, onAlternative)))
}

// listMaskHits is set when the subject is on any list of the mask.
func listMaskHits(api frontend.API, bits []frontend.Variable, onList [NSources]frontend.Variable) frontend.Variable {
	hits := frontend.Variable(0)
	for i, on := range onList {
		hits = api.Add(hits, api.Mul(on, bits[i]))
	}
	return base.NonZero(api, hits)
}
