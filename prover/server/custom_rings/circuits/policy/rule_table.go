package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// ruleBits spans the packed row, from the subject byte up to the opposite mode list mask.
const ruleBits = 104

// ruleFields is a packed rule decoded once, with the predicates every check reads.
type ruleFields struct {
	mode, threshold, altMask        frontend.Variable
	listBits, altBits               []frontend.Variable
	onOwner, onAsset, onSender      frontend.Variable
	present, absent, inline         frontend.Variable
	hasAlternative                  frontend.Variable
	always, scalarGuard, assetGuard frontend.Variable
}

type checkedPolicy struct {
	hash        frontend.Variable
	rules       [NRules]ruleFields
	ruleEnabled []frontend.Variable
	sources     sourcesView
	inline      base.Count
	limits      base.Count
}

// Byte 31 is the subject, then mode, list mask, guard tag, an 8-byte threshold and the opposite mode mask.
func decodeRule(api frontend.API, packed frontend.Variable) ruleFields {
	b := api.ToBinary(packed, ruleBits)
	field := func(from, to int) frontend.Variable {
		return bits.FromBinary(api, b[from:to], bits.WithUnconstrainedInputs())
	}
	is := func(value frontend.Variable, want int) frontend.Variable { return api.IsZero(api.Sub(value, want)) }
	subject, mode, guard, altMask := field(0, 8), field(8, 16), field(24, 32), field(96, 104)
	return ruleFields{
		mode: mode, threshold: field(32, 96), altMask: altMask,
		listBits: b[16:24], altBits: b[96:104],
		onOwner: is(subject, SubjectOutputOwner), onAsset: is(subject, SubjectAsset), onSender: is(subject, SubjectSender),
		present: is(mode, ModePresent), absent: is(mode, ModeAbsent), inline: api.IsZero(field(16, 24)),
		hasAlternative: base.NonZero(api, altMask),
		always:         is(guard, GuardAlways), scalarGuard: is(guard, GuardAboveAmount), assetGuard: is(guard, GuardAboveAmountByAsset),
	}
}

// checkPolicy binds evaluation to the committed rules, sources, inline assets and outflow limits.
func (c *CustomRingPolicyCircuit) checkPolicy(api frontend.API, rc frontend.Rangechecker) checkedPolicy {
	rules := base.SelectCount(api, c.PolicyLen, 0, NRules+1)
	checked := checkedPolicy{ruleEnabled: rules.Active, inline: base.SelectCount(api, c.InlineCount, 0, NInlineAssets+1)}
	checked.sources = c.checkSources(api)
	for i, packed := range c.Rules {
		checked.rules[i] = decodeRule(api, packed)
		checked.rules[i].check(api, rules.Active[i], checked.sources.configured)
	}
	for i, asset := range c.InlineAssets {
		rc.Check(c.InlineLimits[i], amountBits)
		shared.AssertWhen(api, checked.inline.Active[i], base.NonZero(api, asset))
		padding := api.Sub(1, checked.inline.Active[i])
		api.AssertIsEqual(api.Mul(padding, asset), 0)
		api.AssertIsEqual(api.Mul(padding, c.InlineLimits[i]), 0)
	}
	c.checkGuardAssets(api, checked)
	checked.limits = c.checkLimitTable(api, rc)
	checked.hash = c.policyHash(api, rules, checked.inline.Active, checked.limits.Active)
	return checked
}

// check rejects rule combinations the evaluator does not support.
func (r ruleFields) check(api frontend.API, enabled frontend.Variable, configured [NSources]frontend.Variable) {
	shared.AssertWhen(api, enabled, api.Add(r.onOwner, r.onAsset, r.onSender))
	shared.AssertWhen(api, enabled, api.Add(r.present, r.absent))
	api.AssertIsEqual(api.Mul(enabled, r.absent, r.altMask), 0)
	for i := range r.listBits {
		api.AssertIsEqual(api.Mul(enabled, r.listBits[i], r.altBits[i]), 0)
		shared.AssertWhen(api, api.Mul(enabled, api.Or(r.listBits[i], r.altBits[i])), configured[i])
	}
	// Assets have no member record, an asset rule checks the inline allowlist without alternatives.
	shared.AssertWhen(api, api.Mul(enabled, r.onAsset), r.inline)
	inline := api.Mul(enabled, r.inline)
	shared.AssertWhen(api, inline, r.onAsset)
	shared.AssertWhen(api, inline, r.present)
	api.AssertIsEqual(api.Mul(inline, r.altMask), 0)
	shared.AssertWhen(api, enabled, api.Add(r.always, r.scalarGuard, r.assetGuard))
	shared.AssertWhen(api, api.Mul(enabled, r.scalarGuard), base.NonZero(api, r.threshold))
	api.AssertIsEqual(api.Mul(enabled, api.Sub(1, r.scalarGuard), r.threshold), 0)
	shared.AssertWhen(api, api.Mul(enabled, r.onSender), r.always)
	shared.AssertWhen(api, api.Mul(enabled, r.assetGuard), r.onOwner)
}

// Amount guards need one enforced asset for owner totals and distinct limited assets for per-asset totals.
func (c *CustomRingPolicyCircuit) checkGuardAssets(api frontend.API, checked checkedPolicy) {
	ownerGuard, assetGuard, unguardedInline := frontend.Variable(0), frontend.Variable(0), frontend.Variable(0)
	for i, r := range checked.rules {
		enabled := checked.ruleEnabled[i]
		ownerGuard = api.Or(ownerGuard, api.Mul(enabled, r.onOwner, r.scalarGuard))
		assetGuard = api.Or(assetGuard, api.Mul(enabled, r.assetGuard))
		unguardedInline = api.Or(unguardedInline, api.Mul(enabled, r.inline, r.always))
	}
	shared.AssertWhen(api, ownerGuard, api.And(unguardedInline, checked.inline.OneHot[1]))
	shared.AssertWhen(api, assetGuard, checked.inline.Active[0])
	for i, asset := range c.InlineAssets {
		required := api.Mul(assetGuard, checked.inline.Active[i])
		shared.AssertWhen(api, required, base.NonZero(api, c.InlineLimits[i]))
		for j, other := range c.InlineAssets[:i] {
			shared.AssertWhen(api, api.Mul(required, checked.inline.Active[j]), base.NonZero(api, api.Sub(asset, other)))
		}
	}
}

// The section counts bind the boundaries between rules, inline assets and outflow limits.
func (c *CustomRingPolicyCircuit) policyHash(api frontend.API, rules base.Count, inlineEnabled, limitEnabled []frontend.Variable) frontend.Variable {
	preimage := []frontend.Variable{policyTableDomain, PolicyVersion}
	for _, source := range c.Sources {
		preimage = append(preimage, source.ListId, source.Registry)
	}
	head := gadget.HashChain(api, append(preimage, c.PolicyLen, c.InlineCount, c.LimitCount))
	hash := base.ExtendHashPrefix(api, head, c.Rules[:], rules)
	for i, asset := range c.InlineAssets {
		hash = api.Select(inlineEnabled[i], gadget.HashChain(api, []frontend.Variable{hash, asset, c.InlineLimits[i]}), hash)
	}
	for i, row := range c.Limits {
		hash = api.Select(limitEnabled[i], gadget.HashChain(api, []frontend.Variable{hash, row.Asset, row.Cap, row.CosignAbove}), hash)
	}
	return hash
}
