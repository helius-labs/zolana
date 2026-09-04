package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// RuleWires is one compiled policy rule, the policy hash committing only to
// Packed.
type RuleWires struct {
	Packed  frontend.Variable
	Subject frontend.Variable
	Mode    frontend.Variable
	// Mask has bit i set for list i+1, zero marks the inline source.
	Mask frontend.Variable
	// AltMask marks the lists satisfying the rule in the opposite mode.
	AltMask   frontend.Variable
	GuardTag  frontend.Variable
	Threshold frontend.Variable
}

func (c *CustomRingPolicyCircuit) definePolicy(
	api frontend.API,
	checker frontend.Rangechecker,
) (frontend.Variable, [NRules]frontend.Variable) {
	assertOneHot(api, c.LenOneHot[:])
	assertOneHot(api, c.InlineCountOneHot[:])
	inTable := suffixSums(api, c.LenOneHot[:])
	inInline := suffixSums(api, c.InlineCountOneHot[:])

	var enabled [NRules]frontend.Variable
	for k, rule := range c.Rules {
		enabled[k] = inTable[k+1]
		rule.define(api, checker, enabled[k])
	}
	// InlineCount closes both the policy-hash preimage and the membership set.
	// A non-zero value after that prefix would otherwise be uncommitted padding
	// that inlineCoverage could still use to satisfy an asset rule.
	for m, member := range c.InlineAssets {
		checker.Check(c.InlineLimits[m], 64)
		api.AssertIsEqual(api.Mul(api.Sub(1, inInline[m+1]), member), 0)
		api.AssertIsEqual(api.Mul(api.Sub(1, inInline[m+1]), c.InlineLimits[m]), 0)
	}
	return c.policyHash(api), enabled
}

// define holds the inline invariants ring_policy::RuleTableBuilder asserts at
// build time.
func (w RuleWires) define(api frontend.API, checker frontend.Rangechecker, enabled frontend.Variable) {
	checker.Check(w.Subject, 8)
	checker.Check(w.Mode, 8)
	checker.Check(w.Mask, 8)
	checker.Check(w.AltMask, 8)
	checker.Check(w.GuardTag, 8)
	checker.Check(w.Threshold, 64)
	// Mirrors ring_policy::Rule::encoded, byte 31 down to byte 19.
	api.AssertIsEqual(w.Packed, api.Add(
		w.Subject,
		api.Mul(w.Mode, ruleShift[0]),
		api.Mul(w.Mask, ruleShift[1]),
		api.Mul(w.GuardTag, ruleShift[2]),
		api.Mul(w.Threshold, ruleShift[3]),
		api.Mul(w.AltMask, ruleShift[4]),
	))

	isPresent := api.IsZero(api.Sub(w.Mode, ModePresent))
	isAbsent := api.IsZero(api.Sub(w.Mode, ModeAbsent))
	shared.AssertWhen(api, enabled, api.Add(isPresent, isAbsent))

	inline := api.Mul(enabled, api.IsZero(w.Mask))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: inline, A: w.Subject, B: SubjectAsset})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: inline, A: w.Mode, B: ModePresent})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: inline, A: w.AltMask, B: 0})
}

// policyHash mirrors ring_policy::RuleTable::hash, the head's length element
// closing the variable-length preimage.
func (c *CustomRingPolicyCircuit) policyHash(api frontend.API) frontend.Variable {
	length := frontend.Variable(0)
	for size, bit := range c.LenOneHot {
		length = api.Add(length, api.Mul(bit, size))
	}
	preimage := make([]frontend.Variable, 0, 3+2*NSources)
	preimage = append(preimage, policyTableDomain, PolicyVersion)
	for _, src := range c.Sources {
		preimage = append(preimage, src.ListId, src.OwnerHash)
	}
	head := gadget.HashChain(api, append(preimage, length))

	packed := make([]frontend.Variable, NRules)
	for k, rule := range c.Rules {
		packed[k] = rule.Packed
	}
	acc := foldSelect(api, head, packed, c.LenOneHot[:])
	inInline := suffixSums(api, c.InlineCountOneHot[:])
	for m, asset := range c.InlineAssets {
		next := gadget.HashChain(api, []frontend.Variable{acc, asset, c.InlineLimits[m]})
		acc = api.Select(inInline[m+1], next, acc)
	}
	return acc
}
