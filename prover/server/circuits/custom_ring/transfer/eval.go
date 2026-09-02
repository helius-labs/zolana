package transfer

import (
	"github.com/consensys/gnark/frontend"
)

// evaluate closes every enabled rule against every live instance of its
// subject, covered by an answer proving the same (list, mode) fact about
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
		for j := range slots.outputs {
			subjectVal := api.Select(onAsset, slots.outputs[j].asset, slots.outputs[j].owner)
			// The exemption weighs the total sent to the same subject value, a
			// payment split into sub-threshold slots no longer escapes the rule.
			aggregated := frontend.Variable(0)
			for jp := range slots.outputs {
				otherVal := api.Select(onAsset, slots.outputs[jp].asset, slots.outputs[jp].owner)
				liveOther := api.Select(onAsset, liveAsset[jp], liveOwner[jp])
				same := api.IsZero(api.Sub(otherVal, subjectVal))
				aggregated = api.Add(aggregated, api.Mul(api.Mul(liveOther, same), slots.outputs[jp].amount))
			}
			terms := make([]frontend.Variable, NAnswers)
			for e := range matched {
				terms[e] = api.Mul(matched[e], api.Select(onAsset, eqOutputAsset[e][j], eqOutputOwner[e][j]))
			}
			rule.assertGuardedAnswered(
				api,
				api.Mul(onOutput, api.Select(onAsset, liveAsset[j], liveOwner[j])),
				api.Select(isInline, inline[j], anyOf(api, terms)),
				aggregated,
			)
		}

		// Sender rules take no amount guard, an input is answered only by a
		// covering entry.
		onInput := api.Mul(enabled[k], onSender)
		for i := range slots.inputs {
			terms := make([]frontend.Variable, NAnswers)
			for e := range matched {
				terms[e] = api.Mul(matched[e], eqSender[e][i])
			}
			assertCovered(api, api.Mul(onInput, liveSender[i]), anyOf(api, terms))
		}
	}
}

func (w RuleWires) assertGuardedAnswered(api frontend.API, instance, covered, aggregated frontend.Variable) {
	exempt := api.Mul(
		api.IsZero(api.Sub(w.GuardTag, GuardAboveAmount)),
		atMostAggregated(api, aggregated, w.Threshold),
	)
	api.AssertIsEqual(api.Mul(instance, api.Mul(api.Sub(1, covered), api.Sub(1, exempt))), 0)
}

func assertCovered(api frontend.API, instance, covered frontend.Variable) {
	api.AssertIsEqual(api.Mul(instance, api.Sub(1, covered)), 0)
}

// inlineCoverage matches output assets against the policy's inline members, the
// zero padding member never matching.
func (c *Circuit) inlineCoverage(api frontend.API, outputs [NOut]slotView) [NOut]frontend.Variable {
	inInline := suffixSums(api, c.InlineCountOneHot[:])
	var listed [NInlineAssets]frontend.Variable
	for m, member := range c.InlineAssets {
		listed[m] = api.Mul(inInline[m+1], nonZero(api, member))
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

// atMostAggregated returns 1 iff aggregated <= threshold, sound because every
// summed amount is range-checked to 64 bits, the offset sum never wraps.
func atMostAggregated(api frontend.API, aggregated, threshold frontend.Variable) frontend.Variable {
	return api.ToBinary(api.Add(api.Sub(threshold, aggregated), aggregatedOffset), 67)[66]
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
