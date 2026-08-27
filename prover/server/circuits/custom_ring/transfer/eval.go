package transfer

import (
	"github.com/consensys/gnark/frontend"
)

// evaluate closes every enabled rule against every live instance of its
// subject, answered by an answer proving the same (list, mode) fact about
// the instance or by the amount guard.
func (c *Circuit) evaluate(
	api frontend.API,
	slots openings,
	answers [NAnswers]answerView,
	enabled [NRules]frontend.Variable,
) {
	inline := c.inlineCoverage(api, slots.outputs)

	var eqOutputOwner, eqOutputAsset [NAnswers][NOut]frontend.Variable
	var eqSender [NAnswers][NIn]frontend.Variable
	for e, entry := range answers {
		for j, out := range slots.outputs {
			eqOutputOwner[e][j] = api.IsZero(api.Sub(entry.member, out.owner))
			eqOutputAsset[e][j] = api.IsZero(api.Sub(entry.member, out.asset))
		}
		for i, in := range slots.inputs {
			eqSender[e][i] = api.IsZero(api.Sub(entry.member, in.owner))
		}
	}

	// A padding slot opens to zero and carries no obligation.
	var liveOwner, liveAsset [NOut]frontend.Variable
	for j, out := range slots.outputs {
		liveOwner[j] = api.Mul(out.live, nonZero(api, out.owner))
		liveAsset[j] = api.Mul(out.live, nonZero(api, out.asset))
	}
	var liveSender [NIn]frontend.Variable
	for i, in := range slots.inputs {
		liveSender[i] = api.Mul(in.live, nonZero(api, in.owner))
	}

	for k, rule := range c.Rules {
		isInline := api.IsZero(api.Sub(rule.ListId, InlineKind))
		onOutputOwner := api.IsZero(api.Sub(rule.Subject, SubjectOutputOwner))
		onAsset := api.IsZero(api.Sub(rule.Subject, SubjectAsset))
		// SubjectExitDestination has no instance here, nothing constrains a rule
		// carrying it.
		onSender := api.IsZero(api.Sub(rule.Subject, SubjectSender))

		var matched [NAnswers]frontend.Variable
		for e, entry := range answers {
			matched[e] = api.Mul(entry.enabled, api.Mul(
				api.IsZero(api.Sub(entry.listId, rule.ListId)),
				api.IsZero(api.Sub(entry.mode, rule.Mode)),
			))
		}

		onOutput := api.Mul(enabled[k], api.Add(onOutputOwner, onAsset))
		for j, out := range slots.outputs {
			terms := make([]frontend.Variable, NAnswers)
			for e := range matched {
				terms[e] = api.Mul(matched[e], api.Select(onAsset, eqOutputAsset[e][j], eqOutputOwner[e][j]))
			}
			rule.assertAnswered(
				api,
				api.Mul(onOutput, api.Select(onAsset, liveAsset[j], liveOwner[j])),
				api.Select(isInline, inline[j], anyOf(api, terms)),
				out.amount,
			)
		}

		onInput := api.Mul(enabled[k], onSender)
		for i, in := range slots.inputs {
			terms := make([]frontend.Variable, NAnswers)
			for e := range matched {
				terms[e] = api.Mul(matched[e], eqSender[e][i])
			}
			rule.assertAnswered(api, api.Mul(onInput, liveSender[i]), anyOf(api, terms), in.amount)
		}
	}
}

func (w RuleWires) assertAnswered(api frontend.API, instance, covered, amount frontend.Variable) {
	exempt := api.Mul(
		api.IsZero(api.Sub(w.GuardTag, GuardAboveAmount)),
		atMost(api, amount, w.Threshold),
	)
	api.AssertIsEqual(api.Mul(instance, api.Mul(api.Sub(1, covered), api.Sub(1, exempt))), 0)
}

// inlineCoverage matches output assets against the policy's inline members, the
// zero padding member never matching.
func (c *Circuit) inlineCoverage(api frontend.API, outputs [NOut]slotView) [NOut]frontend.Variable {
	var listed [NInlineAssets]frontend.Variable
	for m, member := range c.InlineAssets {
		listed[m] = nonZero(api, member)
	}
	var covered [NOut]frontend.Variable
	for j, out := range outputs {
		terms := make([]frontend.Variable, NInlineAssets)
		for m, member := range c.InlineAssets {
			terms[m] = api.Mul(listed[m], api.IsZero(api.Sub(member, out.asset)))
		}
		covered[j] = anyOf(api, terms)
	}
	return covered
}

// atMost returns 1 iff amount <= threshold, sound only because both are
// range-checked to 64 bits and the offset sum cannot wrap.
func atMost(api frontend.API, amount, threshold frontend.Variable) frontend.Variable {
	return api.ToBinary(api.Add(api.Sub(threshold, amount), amountOffset), 65)[64]
}

// anyOf ORs boolean terms by summing, sound while the term count stays far
// below the field modulus.
func anyOf(api frontend.API, terms []frontend.Variable) frontend.Variable {
	sum := frontend.Variable(0)
	for _, term := range terms {
		sum = api.Add(sum, term)
	}
	return nonZero(api, sum)
}

func nonZero(api frontend.API, value frontend.Variable) frontend.Variable {
	return api.Sub(1, api.IsZero(value))
}
