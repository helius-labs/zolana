package policy

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

type Table struct {
	Sources   [NSources]SourceWires
	PolicyLen frontend.Variable
	// Each rule is its 32-byte row read as one field.
	Rules        [NRules]frontend.Variable
	InlineAssets [NInlineAssets]frontend.Variable
	InlineLimits [NInlineAssets]frontend.Variable
	InlineCount  frontend.Variable
	Limits       [NOutflowLimits]OutflowLimitWires
	LimitCount   frontend.Variable
}

// SourceWires is slot i of the source map, list i+1 and its registry field, zero for the ring's own.
type SourceWires struct {
	ListID   frontend.Variable
	Registry frontend.Variable
}

// OutflowLimitWires bounds one asset's outflow per transfer, a zero cap or co-sign bound is off.
type OutflowLimitWires struct {
	Asset       frontend.Variable
	Cap         frontend.Variable
	CosignAbove frontend.Variable
}

type tableView struct {
	rules                                 [NRules]ruleFields
	ruleActive, inlineActive, limitActive []frontend.Variable
	sources                               sourceView
	// assetRules is set when an active rule reads asset lists.
	assetRules frontend.Variable
	// scalarOwner is set when an active owner rule carries a scalar guard.
	scalarOwner frontend.Variable
}

type sourceView struct {
	foreign    [NSources]frontend.Variable
	anyForeign frontend.Variable
}

type ruleFields struct {
	threshold frontend.Variable
	// A subject on list i+1 adds admitWeight[i] to admitBase.
	admitBase                  frontend.Variable
	admitWeight                [NSources]frontend.Variable
	onOwner, onAsset, onSender frontend.Variable
	scalarGuard, assetGuard    frontend.Variable
}

// ruleParts lays out a rule row from its low byte as Row does, subject, mode, list mask, guard, threshold, alternative mask.
var ruleParts = [...]struct{ shift, width uint }{{0, 8}, {8, 8}, {16, 8}, {24, 8}, {32, 64}, {96, 8}}

// decode binds the table to policy_hash, the program validated it at write time (EncodedRuleTable::validate).
func (t Table) decode(api frontend.API, rc frontend.Rangechecker, policyHash frontend.Variable) tableView {
	// 1. The rules read the table the program hashed at its last policy write.
	api.AssertIsEqual(policyHash, t.hash(api))
	// 2. Each count selects its active rows, a count past its capacity selects none and fails.
	d := tableView{
		ruleActive:   gadget.SelectCount(api, t.PolicyLen, 0, NRules+1).Active,
		inlineActive: gadget.SelectCount(api, t.InlineCount, 0, NInlineAssets+1).Active,
		limitActive:  gadget.SelectCount(api, t.LimitCount, 0, NOutflowLimits+1).Active,
		sources:      t.readSources(api),
		assetRules:   0,
		scalarOwner:  0,
	}
	// 3. Every rule decodes once, the flags later steps gate on fold over the active rules.
	for i, packed := range t.Rules {
		rule := decodeRule(api, rc, packed)
		d.rules[i] = rule
		d.assetRules = api.Or(d.assetRules, api.Mul(d.ruleActive[i], rule.onAsset))
		d.scalarOwner = api.Or(d.scalarOwner, api.Mul(d.ruleActive[i], rule.onOwner, rule.scalarGuard))
	}
	return d
}

// Fields lists the hashed fields in EncodedRuleTable::fields order.
func (t Table) Fields() []frontend.Variable {
	fields := make([]frontend.Variable, 0, PolicyTableFields)
	fields = append(fields, base.PolicyTableDomain, PolicyTableVersion)
	for _, source := range t.Sources {
		fields = append(fields, source.ListID, source.Registry)
	}
	fields = append(fields, t.PolicyLen, t.InlineCount, t.LimitCount)
	fields = append(fields, t.Rules[:]...)
	fields = append(fields, t.InlineAssets[:]...)
	fields = append(fields, t.InlineLimits[:]...)
	for _, limit := range t.Limits {
		fields = append(fields, limit.Asset, limit.Cap, limit.CosignAbove)
	}
	return fields
}

// hash absorbs the fields PolicyTableRate at a time beside the accumulator, as EncodedRuleTable::hash does.
func (t Table) hash(api frontend.API) frontend.Variable {
	fields := t.Fields()
	accumulator := frontend.Variable(0)
	for start := 0; start < len(fields); start += PolicyTableRate {
		accumulator = gadget.PoseidonHash(api, append([]frontend.Variable{accumulator}, fields[start:start+PolicyTableRate]...))
	}
	return accumulator
}

// readSources marks list i+1 foreign when slot i names a registry field, one curator registry serves them all.
func (t Table) readSources(api frontend.API) sourceView {
	var view sourceView
	for i, source := range t.Sources {
		view.foreign[i] = gadget.IsNonZero(api, source.Registry)
	}
	view.anyForeign = gadget.IsAny(api, view.foreign[:]...)
	return view
}

func decodeRule(api frontend.API, rc frontend.Rangechecker, packed frontend.Variable) ruleFields {
	// 1. The hint proposes the parts, untrusted until the range checks and the recomposition bind them.
	parts, err := api.Compiler().NewHint(rulePartsHint, len(ruleParts), packed)
	if err != nil {
		panic(err)
	}
	subject, mode, mask, guard, threshold, alternative := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
	// 2. Subject, mode, guard and threshold stay inside their widths, the recomposition stays below 2^104.
	for _, i := range []int{0, 1, 3, 4} {
		rc.Check(parts[i], int(ruleParts[i].width))
	}
	// 3. Both list masks split into one bit per source slot, bit i marks list i+1.
	listBits, altBits := api.ToBinary(mask, NSources), api.ToBinary(alternative, NSources)
	recomposed := frontend.Variable(0)
	for i, part := range ruleParts {
		recomposed = api.Add(recomposed, api.Mul(parts[i], new(big.Int).Lsh(big.NewInt(1), part.shift)))
	}
	// 4. The bounded parts recompose to the hashed row over the integers, no part can alias another.
	api.AssertIsEqual(recomposed, packed)
	is := func(value frontend.Variable, want int) frontend.Variable { return api.IsZero(api.Sub(value, want)) }
	rule := ruleFields{
		threshold:   threshold,
		admitBase:   0,
		onOwner:     is(subject, SubjectOutputOwner),
		onAsset:     is(subject, SubjectAsset),
		onSender:    is(subject, SubjectSender),
		scalarGuard: is(guard, GuardAboveAmount),
		assetGuard:  is(guard, GuardAboveAmountByAsset),
	}
	// 5. A list of a present mask admits a subject on it, a list of an absent or the alternative mask a subject off it.
	present := is(mode, ModePresent)
	for i := range rule.admitWeight {
		inPresent := api.Mul(present, listBits[i])
		inAbsent := api.Sub(api.Add(listBits[i], altBits[i]), inPresent)
		rule.admitBase = api.Add(rule.admitBase, inAbsent)
		rule.admitWeight[i] = api.Sub(inPresent, inAbsent)
	}
	return rule
}

func init() { solver.RegisterHint(rulePartsHint) }

// rulePartsHint splits a row along ruleParts, decodeRule range checks and recomposes every output.
func rulePartsHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) != len(ruleParts) {
		return errors.New("rule parts: want one row and one output per part")
	}
	for i, part := range ruleParts {
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), part.width), big.NewInt(1))
		outputs[i].Rsh(inputs[0], part.shift).And(outputs[i], mask)
	}
	return nil
}
