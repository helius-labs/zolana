// Checks policy encoding and permitted rule combinations, reconstructing
// the policy hash that binds evaluation to the ring's configuration.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// RuleWires exposes a committed requirement for checking each applicable
// transaction subject.
type RuleWires struct {
	// Only the encoded row enters the policy hash.
	Packed  frontend.Variable
	Subject frontend.Variable
	Mode    frontend.Variable
	// A zero ListMask selects inline assets, otherwise bit i selects list
	// i+1 in Mode.
	ListMask frontend.Variable
	// AltListMask selects lists in the opposite mode.
	AltListMask frontend.Variable
	// Amount guards waive coverage at or below the selected threshold.
	GuardTag frontend.Variable
	// Only GuardAboveAmount uses the scalar threshold.
	Threshold frontend.Variable
}

// checkPolicy binds evaluation to the committed rules, source map and inline
// assets.
func (c *CustomRingPolicyCircuit) checkPolicy(
	api frontend.API,
	checker frontend.Rangechecker,
) (frontend.Variable, [NRules]frontend.Variable, [NInlineAssets]frontend.Variable) {
	// 1. Select the committed rule and inline asset prefixes.
	assertOneHot(api, c.RuleCountSelected[:])
	assertOneHot(api, c.InlineAssetCountSelected[:])
	inTable := suffixSums(api, c.RuleCountSelected[:])
	inInline := suffixSums(api, c.InlineAssetCountSelected[:])
	var ruleEnabled [NRules]frontend.Variable
	var inlineEnabled [NInlineAssets]frontend.Variable
	copy(ruleEnabled[:], inTable[1:])
	copy(inlineEnabled[:], inInline[1:])

	// 2. Check the namespace owner configured for each list.
	sources := c.checkSources(api)

	// 3. Bind valid rule fields to their encoded rows and configured
	// sources.
	for i, rule := range c.Rules {
		rule.check(api, checker, ruleEnabled[i], sources)
	}

	// 4. Bound inline limits and exclude zero members and nonzero padding.
	for i, asset := range c.InlineAssets {
		checker.Check(c.InlineLimits[i], amountBits)
		shared.AssertWhen(api, inlineEnabled[i], nonZero(api, asset))
		api.AssertIsEqual(api.Mul(api.Sub(1, inlineEnabled[i]), asset), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, inlineEnabled[i]), c.InlineLimits[i]), 0)
	}

	// 5. Establish the asset units required by amount guards.
	c.checkGuardAssets(api, ruleEnabled, inlineEnabled)

	// 6. Commit to the checked policy fields.
	return c.policyHash(api, inlineEnabled), ruleEnabled, inlineEnabled
}

// check binds decoded fields to the row and rejects unsupported rule
// combinations.
func (w RuleWires) check(api frontend.API, checker frontend.Rangechecker, enabled frontend.Variable, sources [NSources]frontend.Variable) {
	// 1. Bound every encoded field and decode the list masks.
	checker.Check(w.Subject, 8)
	checker.Check(w.Mode, 8)
	checker.Check(w.GuardTag, 8)
	checker.Check(w.Threshold, amountBits)
	listBits := api.ToBinary(w.ListMask, NSources)
	altBits := api.ToBinary(w.AltListMask, NSources)

	// 2. Bind the decoded fields to Packed.
	api.AssertIsEqual(w.Packed, api.Add(
		w.Subject,
		api.Mul(w.Mode, ruleWeights.mode),
		api.Mul(w.ListMask, ruleWeights.listMask),
		api.Mul(w.GuardTag, ruleWeights.guardTag),
		api.Mul(w.Threshold, ruleWeights.threshold),
		api.Mul(w.AltListMask, ruleWeights.altListMask),
	))

	// 3. Check subjects and modes, allowing AltListMask only for Present.
	onOwner := api.IsZero(api.Sub(w.Subject, SubjectOutputOwner))
	onAsset := api.IsZero(api.Sub(w.Subject, SubjectAsset))
	onSender := api.IsZero(api.Sub(w.Subject, SubjectSender))
	shared.AssertWhen(api, enabled, api.Add(onOwner, onAsset, onSender))
	isPresent := api.IsZero(api.Sub(w.Mode, ModePresent))
	isAbsent := api.IsZero(api.Sub(w.Mode, ModeAbsent))
	shared.AssertWhen(api, enabled, api.Add(isPresent, isAbsent))
	api.AssertIsEqual(api.Mul(enabled, isAbsent, w.AltListMask), 0)

	// 4. Require disjoint list alternatives with configured sources.
	for i := range listBits {
		api.AssertIsEqual(api.Mul(enabled, listBits[i], altBits[i]), 0)
		referenced := api.Or(listBits[i], altBits[i])
		shared.AssertWhen(api, api.Mul(enabled, referenced), sources[i])
	}

	// 5. Restrict inline rules to asset presence without alternatives.
	inline := api.Mul(enabled, api.IsZero(w.ListMask))
	shared.AssertWhen(api, inline, onAsset)
	shared.AssertWhen(api, inline, isPresent)
	api.AssertIsEqual(api.Mul(inline, w.AltListMask), 0)

	// 6. Check guard tags, thresholds and permitted subjects.
	always := api.IsZero(api.Sub(w.GuardTag, GuardAlways))
	scalar := api.IsZero(api.Sub(w.GuardTag, GuardAboveAmount))
	perAsset := api.IsZero(api.Sub(w.GuardTag, GuardAboveAmountByAsset))
	shared.AssertWhen(api, enabled, api.Add(always, scalar, perAsset))
	shared.AssertWhen(api, api.Mul(enabled, scalar), nonZero(api, w.Threshold))
	api.AssertIsEqual(api.Mul(enabled, api.Sub(1, scalar), w.Threshold), 0)
	shared.AssertWhen(api, api.Mul(enabled, onSender), always)
	shared.AssertWhen(api, api.Mul(enabled, perAsset), onOwner)
}

// checkGuardAssets establishes consistent asset units for amount exemptions.
func (c *CustomRingPolicyCircuit) checkGuardAssets(api frontend.API, ruleEnabled [NRules]frontend.Variable, inlineEnabled [NInlineAssets]frontend.Variable) {
	// 1. Collect asset requirements from enabled guards.
	ownerGuard := frontend.Variable(0)
	perAssetGuard := frontend.Variable(0)
	unguardedInline := frontend.Variable(0)
	for i, rule := range c.Rules {
		onOwner := api.IsZero(api.Sub(rule.Subject, SubjectOutputOwner))
		scalar := api.IsZero(api.Sub(rule.GuardTag, GuardAboveAmount))
		perAsset := api.IsZero(api.Sub(rule.GuardTag, GuardAboveAmountByAsset))
		inline := api.IsZero(rule.ListMask)
		always := api.IsZero(api.Sub(rule.GuardTag, GuardAlways))
		ownerGuard = api.Or(ownerGuard, api.Mul(ruleEnabled[i], onOwner, scalar))
		perAssetGuard = api.Or(perAssetGuard, api.Mul(ruleEnabled[i], perAsset))
		unguardedInline = api.Or(unguardedInline, api.Mul(ruleEnabled[i], inline, always))
	}

	// 2. Require one enforced asset for scalar owner totals.
	shared.AssertWhen(api, ownerGuard, api.And(unguardedInline, c.InlineAssetCountSelected[1]))

	// 3. Require distinct assets with positive limits for per-asset totals.
	shared.AssertWhen(api, perAssetGuard, inlineEnabled[0])
	for i, asset := range c.InlineAssets {
		required := api.Mul(perAssetGuard, inlineEnabled[i])
		shared.AssertWhen(api, required, nonZero(api, c.InlineLimits[i]))
		for j := 0; j < i; j++ {
			shared.AssertWhen(api, api.Mul(required, inlineEnabled[j]), nonZero(api, api.Sub(asset, c.InlineAssets[j])))
		}
	}
}

// policyHash reproduces the ring's commitment to its sources, rules and inline
// asset limits.
func (c *CustomRingPolicyCircuit) policyHash(api frontend.API, inlineEnabled [NInlineAssets]frontend.Variable) frontend.Variable {
	// 1. Decode the committed rule count.
	length := frontend.Variable(0)
	for size, bit := range c.RuleCountSelected {
		length = api.Add(length, api.Mul(bit, size))
	}

	// 2. Hash the domain, version, source map and rule count.
	preimage := make([]frontend.Variable, 0, 3+2*NSources)
	preimage = append(preimage, policyTableDomain, PolicyVersion)
	for _, source := range c.Sources {
		preimage = append(preimage, source.ListId, source.OwnerHash)
	}
	head := gadget.HashChain(api, append(preimage, length))

	// 3. Append the selected packed rules.
	packed := make([]frontend.Variable, NRules)
	for i, rule := range c.Rules {
		packed[i] = rule.Packed
	}
	hash := extendHashPrefix(api, head, packed, c.RuleCountSelected[:])

	// 4. Append each active inline asset and its limit in order.
	for i, asset := range c.InlineAssets {
		next := gadget.HashChain(api, []frontend.Variable{hash, asset, c.InlineLimits[i]})
		hash = api.Select(inlineEnabled[i], next, hash)
	}
	return hash
}

// matchListAndMode selects list fact alternatives before member matching
// against subjects.
func (w RuleWires) matchListAndMode(api frontend.API, listFacts [NListFacts]listFact, onList [NListFacts][NSources]frontend.Variable) [NListFacts]frontend.Variable {
	// 1. Decode the lists for each mode.
	listBits := api.ToBinary(w.ListMask, NSources)
	altBits := api.ToBinary(w.AltListMask, NSources)
	altMode := api.Sub(ModePresent+ModeAbsent, w.Mode)

	// 2. Match each enabled list fact to either list-and-mode alternative.
	var matches [NListFacts]frontend.Variable
	for i, fact := range listFacts {
		primary := api.Mul(listInMask(api, listBits, onList[i][:]), api.IsZero(api.Sub(fact.mode, w.Mode)))
		alternative := api.Mul(listInMask(api, altBits, onList[i][:]), api.IsZero(api.Sub(fact.mode, altMode)))
		matches[i] = api.Mul(fact.enabled, api.Or(primary, alternative))
	}
	return matches
}

// listInMask tests whether a rule mask selects the fact's list.
func listInMask(api frontend.API, bits, onList []frontend.Variable) frontend.Variable {
	selected := frontend.Variable(0)
	for i, named := range onList {
		selected = api.Add(selected, api.Mul(named, bits[i]))
	}
	return selected
}
