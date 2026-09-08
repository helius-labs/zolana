package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// Only Packed enters the policy commitment.
type RuleWires struct {
	Packed  frontend.Variable
	Subject frontend.Variable
	Mode    frontend.Variable
	// Bit i selects list i+1 in Mode.
	ListMask frontend.Variable
	// AltListMask selects lists in the opposite mode.
	AltListMask frontend.Variable
	GuardTag    frontend.Variable
	Threshold   frontend.Variable
}

func (c *CustomRingPolicyCircuit) checkPolicy(
	api frontend.API,
	checker frontend.Rangechecker,
) (frontend.Variable, [NRules]frontend.Variable, [NInlineAssets]frontend.Variable) {
	// Select the committed rules and inline assets.
	assertOneHot(api, c.RuleCountOneHot[:])
	assertOneHot(api, c.InlineCountOneHot[:])
	inTable := suffixSums(api, c.RuleCountOneHot[:])
	inInline := suffixSums(api, c.InlineCountOneHot[:])
	var ruleEnabled [NRules]frontend.Variable
	var inlineEnabled [NInlineAssets]frontend.Variable
	copy(ruleEnabled[:], inTable[1:])
	copy(inlineEnabled[:], inInline[1:])

	// Bind each rule to its encoded row and configured sources.
	sources := c.checkSources(api)
	for i, rule := range c.Rules {
		rule.check(api, checker, ruleEnabled[i], sources)
	}

	// Inline padding contributes neither membership nor limits.
	for i, asset := range c.InlineAssets {
		checker.Check(c.InlineLimits[i], amountBits)
		shared.AssertWhen(api, inlineEnabled[i], nonZero(api, asset))
		api.AssertIsEqual(api.Mul(api.Sub(1, inlineEnabled[i]), asset), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, inlineEnabled[i]), c.InlineLimits[i]), 0)
	}
	c.checkGuardAssets(api, ruleEnabled, inlineEnabled)
	return c.policyHash(api, inlineEnabled), ruleEnabled, inlineEnabled
}

func (w RuleWires) check(api frontend.API, checker frontend.Rangechecker, enabled frontend.Variable, sources [NSources]frontend.Variable) {
	// Bind the decoded fields to Packed.
	checker.Check(w.Subject, 8)
	checker.Check(w.Mode, 8)
	checker.Check(w.GuardTag, 8)
	checker.Check(w.Threshold, amountBits)
	listBits := api.ToBinary(w.ListMask, NSources)
	altBits := api.ToBinary(w.AltListMask, NSources)
	api.AssertIsEqual(w.Packed, api.Add(
		w.Subject,
		api.Mul(w.Mode, ruleWeights.mode),
		api.Mul(w.ListMask, ruleWeights.listMask),
		api.Mul(w.GuardTag, ruleWeights.guardTag),
		api.Mul(w.Threshold, ruleWeights.threshold),
		api.Mul(w.AltListMask, ruleWeights.altListMask),
	))

	// Enabled rules use supported subjects and modes.
	onOwner := api.IsZero(api.Sub(w.Subject, SubjectOutputOwner))
	onAsset := api.IsZero(api.Sub(w.Subject, SubjectAsset))
	onSender := api.IsZero(api.Sub(w.Subject, SubjectSender))
	shared.AssertWhen(api, enabled, api.Add(onOwner, onAsset, onSender))
	isPresent := api.IsZero(api.Sub(w.Mode, ModePresent))
	isAbsent := api.IsZero(api.Sub(w.Mode, ModeAbsent))
	shared.AssertWhen(api, enabled, api.Add(isPresent, isAbsent))
	api.AssertIsEqual(api.Mul(enabled, isAbsent, w.AltListMask), 0)

	// Every alternative has one mode and a configured source.
	for i := range listBits {
		api.AssertIsEqual(api.Mul(enabled, listBits[i], altBits[i]), 0)
		referenced := api.Or(listBits[i], altBits[i])
		shared.AssertWhen(api, api.Mul(enabled, referenced), sources[i])
	}
	inline := api.Mul(enabled, api.IsZero(w.ListMask))
	shared.AssertWhen(api, inline, onAsset)
	shared.AssertWhen(api, inline, isPresent)
	api.AssertIsEqual(api.Mul(inline, w.AltListMask), 0)

	always := api.IsZero(api.Sub(w.GuardTag, GuardAlways))
	scalar := api.IsZero(api.Sub(w.GuardTag, GuardAboveAmount))
	perAsset := api.IsZero(api.Sub(w.GuardTag, GuardAboveAmountByAsset))
	shared.AssertWhen(api, enabled, api.Add(always, scalar, perAsset))
	shared.AssertWhen(api, api.Mul(enabled, scalar), nonZero(api, w.Threshold))
	api.AssertIsEqual(api.Mul(enabled, api.Sub(1, scalar), w.Threshold), 0)
	shared.AssertWhen(api, api.Mul(enabled, onSender), always)
	shared.AssertWhen(api, api.Mul(enabled, perAsset), onOwner)
}

func (c *CustomRingPolicyCircuit) checkGuardAssets(api frontend.API, ruleEnabled [NRules]frontend.Variable, inlineEnabled [NInlineAssets]frontend.Variable) {
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

	// Scalar owner totals require one enforced asset.
	shared.AssertWhen(api, ownerGuard, api.And(unguardedInline, c.InlineCountOneHot[1]))

	// Per-asset totals require distinct assets with positive limits.
	shared.AssertWhen(api, perAssetGuard, inlineEnabled[0])
	for i, asset := range c.InlineAssets {
		required := api.Mul(perAssetGuard, inlineEnabled[i])
		shared.AssertWhen(api, required, nonZero(api, c.InlineLimits[i]))
		for j := 0; j < i; j++ {
			shared.AssertWhen(api, api.Mul(required, inlineEnabled[j]), nonZero(api, api.Sub(asset, c.InlineAssets[j])))
		}
	}
}

func (c *CustomRingPolicyCircuit) policyHash(api frontend.API, inlineEnabled [NInlineAssets]frontend.Variable) frontend.Variable {
	length := frontend.Variable(0)
	for size, bit := range c.RuleCountOneHot {
		length = api.Add(length, api.Mul(bit, size))
	}
	// The head binds the version, source map and rule count.
	preimage := make([]frontend.Variable, 0, 3+2*NSources)
	preimage = append(preimage, policyTableDomain, PolicyVersion)
	for _, source := range c.Sources {
		preimage = append(preimage, source.ListId, source.OwnerHash)
	}
	head := gadget.HashChain(api, append(preimage, length))

	// Only the selected rule prefix enters the commitment.
	packed := make([]frontend.Variable, NRules)
	for i, rule := range c.Rules {
		packed[i] = rule.Packed
	}
	hash := extendHashPrefix(api, head, packed, c.RuleCountOneHot[:])
	for i, asset := range c.InlineAssets {
		next := gadget.HashChain(api, []frontend.Variable{hash, asset, c.InlineLimits[i]})
		hash = api.Select(inlineEnabled[i], next, hash)
	}
	return hash
}

func (w RuleWires) matchListAndMode(api frontend.API, answers [NAnswers]answerView, onList [NAnswers][NSources]frontend.Variable) [NAnswers]frontend.Variable {
	listBits := api.ToBinary(w.ListMask, NSources)
	altBits := api.ToBinary(w.AltListMask, NSources)
	altMode := api.Sub(ModePresent+ModeAbsent, w.Mode)
	var matches [NAnswers]frontend.Variable
	for i, answer := range answers {
		primary := api.Mul(listInMask(api, listBits, onList[i][:]), api.IsZero(api.Sub(answer.mode, w.Mode)))
		alternative := api.Mul(listInMask(api, altBits, onList[i][:]), api.IsZero(api.Sub(answer.mode, altMode)))
		matches[i] = api.Mul(answer.enabled, api.Or(primary, alternative))
	}
	return matches
}

func listInMask(api frontend.API, bits, onList []frontend.Variable) frontend.Variable {
	selected := frontend.Variable(0)
	for i, named := range onList {
		selected = api.Add(selected, api.Mul(named, bits[i]))
	}
	return selected
}
