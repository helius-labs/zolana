package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

type outputTotals struct {
	byOwner, byAsset, byOwnerAndAsset frontend.Variable
}

type assetLimit struct {
	found, threshold frontend.Variable
}

// assertRules requires every enabled rule to hold for the sender and for every live output owner and asset, or an amount guard to exempt it.
func (p *Policy) assertRules(api frontend.API, cmp comparator, t tableView, s subjects, outputs []utxoView) {
	// 1. A zero owner carries no obligation, an asset needs no such gate since SPP refuses a UTXO of asset 0.
	liveOwner := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		liveOwner[o] = api.Mul(out.utxo, base.IsNonZero(api, out.ownerPkHash))
	}
	// 2. An asset guard exempts an owner whose outputs of one asset stay within the asset's inline limit.
	totals := sumOutputs(api, outputs, liveOwner)
	limits, assetExempt := make([]assetLimit, len(outputs)), make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		limits[o] = p.inlineLimit(api, t, out.asset)
		assetExempt[o] = cmp.atMost(api, totals[o].byOwnerAndAsset, limits[o].threshold)
	}
	// 3. A scalar guard sums one owner's outputs, under one every UTXO output carries one asset.
	for i, left := range outputs {
		for _, right := range outputs[:i] {
			abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: api.Mul(t.scalarOwner, left.utxo, right.utxo), A: left.asset, B: right.asset})
		}
	}
	// 4. Every active rule holds for its subjects, the sender once and each live output owner or asset.
	for r, rule := range t.rules {
		// The one sender meets every sender rule, with or without a spent input.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(t.ruleActive[r], rule.onSender), V: rule.refuses(api, s.sender.onList)})
		onOutput := api.Mul(t.ruleActive[r], api.Add(rule.onOwner, rule.onAsset))
		for o := range outputs {
			enabled := api.Mul(onOutput, api.Select(rule.onAsset, outputs[o].utxo, liveOwner[o]))
			refused := rule.refuses(api, subjectLists(api, rule.onAsset, s.assets[o], s.owners[o]))
			// An asset guarded rule needs an inline limit for the output's asset.
			shared.AssertWhen(api, api.Mul(enabled, rule.assetGuard), limits[o].found)
			total := api.Select(rule.onAsset, totals[o].byAsset, totals[o].byOwner)
			scalar := api.Mul(rule.scalarGuard, cmp.atMost(api, total, rule.threshold))
			exempt := api.Or(scalar, api.Mul(rule.assetGuard, assetExempt[o]))
			// A subject the lists refuse needs its amounts within the rule's guard.
			shared.AssertWhen(api, api.Mul(enabled, refused), exempt)
		}
	}
}

// sumOutputs totals every output's group, each output pair compares owner and asset once.
func sumOutputs(api frontend.API, outputs []utxoView, liveOwner []frontend.Variable) []outputTotals {
	ownerAmounts, assetAmounts := make([]frontend.Variable, len(outputs)), make([]frontend.Variable, len(outputs))
	totals := make([]outputTotals, len(outputs))
	for o, out := range outputs {
		ownerAmounts[o], assetAmounts[o] = api.Mul(liveOwner[o], out.amount), api.Mul(out.utxo, out.amount)
		totals[o] = outputTotals{byOwner: ownerAmounts[o], byAsset: assetAmounts[o], byOwnerAndAsset: ownerAmounts[o]}
	}
	for i := range outputs {
		for j := range outputs[:i] {
			sameOwner := api.IsZero(api.Sub(outputs[i].ownerPkHash, outputs[j].ownerPkHash))
			sameAsset := api.IsZero(api.Sub(outputs[i].asset, outputs[j].asset))
			for _, pair := range [2][2]int{{i, j}, {j, i}} {
				into, from := pair[0], pair[1]
				owned := api.Mul(sameOwner, ownerAmounts[from])
				totals[into].byOwner = api.Add(totals[into].byOwner, owned)
				totals[into].byAsset = api.Add(totals[into].byAsset, api.Mul(sameAsset, assetAmounts[from]))
				totals[into].byOwnerAndAsset = api.Add(totals[into].byOwnerAndAsset, api.Mul(sameAsset, owned))
			}
		}
	}
	return totals
}

// inlineLimit is the active inline row naming asset, the program keeps inline assets pairwise distinct so at most one matches.
func (p *Policy) inlineLimit(api frontend.API, t tableView, asset frontend.Variable) assetLimit {
	limit := assetLimit{found: 0, threshold: 0}
	for i, inline := range p.InlineAssets {
		match := api.Mul(t.inlineActive[i], api.IsZero(api.Sub(inline, asset)))
		limit.found = api.Add(limit.found, match)
		limit.threshold = api.Add(limit.threshold, api.Mul(match, p.InlineLimits[i]))
	}
	return limit
}

// refuses is set when no list admits the subject, neither a present list it is on nor an absent list it is off.
func (r ruleFields) refuses(api frontend.API, onList [NSources]frontend.Variable) frontend.Variable {
	admitting := r.admitBase
	for i, on := range onList {
		admitting = api.Add(admitting, api.Mul(on, r.admitWeight[i]))
	}
	// Each list adds 0, 1 or 2, the count is zero exactly when no list admits the subject.
	return api.IsZero(admitting)
}

func subjectLists(api frontend.API, onAsset frontend.Variable, asset, owner subjectView) [NSources]frontend.Variable {
	var onList [NSources]frontend.Variable
	for i := range onList {
		onList[i] = api.Select(onAsset, asset.onList[i], owner.onList[i])
	}
	return onList
}
