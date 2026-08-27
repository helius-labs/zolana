package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
)

// RuleWires is one compiled policy rule, the policy hash committing only to
// Packed.
type RuleWires struct {
	Packed    frontend.Variable
	Subject   frontend.Variable
	Mode      frontend.Variable
	ListId    frontend.Variable
	GuardTag  frontend.Variable
	Threshold frontend.Variable
}

func (c *Circuit) definePolicy(
	api frontend.API,
	checker frontend.Rangechecker,
) (frontend.Variable, [NRules]frontend.Variable) {
	assertOneHot(api, c.LenOneHot[:])
	assertOneHot(api, c.InlineCountOneHot[:])
	inTable := suffixSums(api, c.LenOneHot[:])

	var enabled [NRules]frontend.Variable
	for k, rule := range c.Rules {
		enabled[k] = inTable[k+1]
		rule.define(api, checker, enabled[k])
	}
	return c.policyHash(api), enabled
}

// define holds the inline invariants ring_policy::RuleTableBuilder asserts at
// build time.
func (w RuleWires) define(api frontend.API, checker frontend.Rangechecker, enabled frontend.Variable) {
	checker.Check(w.Subject, 8)
	checker.Check(w.Mode, 8)
	checker.Check(w.ListId, 8)
	checker.Check(w.GuardTag, 8)
	checker.Check(w.Threshold, 64)
	// Mirrors ring_policy::Rule::encoded, byte 31 down to byte 20.
	api.AssertIsEqual(w.Packed, api.Add(
		w.Subject,
		api.Mul(w.Mode, ruleShift[0]),
		api.Mul(w.ListId, ruleShift[1]),
		api.Mul(w.GuardTag, ruleShift[2]),
		api.Mul(w.Threshold, ruleShift[3]),
	))

	inline := api.Mul(enabled, api.IsZero(api.Sub(w.ListId, InlineKind)))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: inline, A: w.Subject, B: SubjectAsset})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: inline, A: w.Mode, B: ModePresent})
}

// policyHash mirrors ring_policy::RuleTable::hash, the head's length element
// closing the variable-length preimage.
func (c *Circuit) policyHash(api frontend.API) frontend.Variable {
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
	afterRules := foldSelect(api, head, packed, c.LenOneHot[:])
	return foldSelect(api, afterRules, c.InlineAssets[:], c.InlineCountOneHot[:])
}
