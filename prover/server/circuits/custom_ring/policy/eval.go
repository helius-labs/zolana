package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/spp_transaction/shared"
)

func (c *CustomRingPolicyCircuit) evaluate(
	api frontend.API,
	slots openings,
	answers [NAnswers]answerView,
	ruleEnabled [NRules]frontend.Variable,
	inlineEnabled [NInlineAssets]frontend.Variable,
) {
	// Answers can satisfy several rules and transaction slots.
	var eqOutputOwner, eqOutputAsset [NAnswers][NOut]frontend.Variable
	var eqSender [NAnswers][NIn]frontend.Variable
	var onList [NAnswers][NSources]frontend.Variable
	for answerIndex, answer := range answers {
		for outputIndex, output := range slots.outputs {
			eqOutputOwner[answerIndex][outputIndex] = api.IsZero(api.Sub(answer.member, output.ownerPkHash))
			eqOutputAsset[answerIndex][outputIndex] = api.IsZero(api.Sub(answer.member, output.asset))
		}
		for inputIndex, input := range slots.inputs {
			eqSender[answerIndex][inputIndex] = api.IsZero(api.Sub(answer.member, input.ownerPkHash))
		}
		for listIndex := range onList[answerIndex] {
			onList[answerIndex][listIndex] = api.IsZero(api.Sub(answer.listId, listIndex+1))
		}
	}

	// Zero subjects and non-UTXO slots have no obligation.
	var liveOwner, liveAsset [NOut]frontend.Variable
	for i, output := range slots.outputs {
		liveOwner[i] = api.Mul(output.live, nonZero(api, output.ownerPkHash))
		liveAsset[i] = api.Mul(output.live, nonZero(api, output.asset))
	}
	var liveSender [NIn]frontend.Variable
	for i, input := range slots.inputs {
		liveSender[i] = api.Mul(input.live, nonZero(api, input.ownerPkHash))
	}
	limits := c.matchInlineAssets(api, slots.outputs, inlineEnabled)
	totals := sumOutputs(api, slots.outputs, liveOwner, liveAsset)

	// Every rule must pass for every applicable subject.
	for ruleIndex, rule := range c.Rules {
		isInline := api.IsZero(rule.ListMask)
		hasPerAssetGuard := api.IsZero(api.Sub(rule.GuardTag, GuardAboveAmountByAsset))
		onOwner := api.IsZero(api.Sub(rule.Subject, SubjectOutputOwner))
		onAsset := api.IsZero(api.Sub(rule.Subject, SubjectAsset))
		onSender := api.IsZero(api.Sub(rule.Subject, SubjectSender))
		listAndModeMatches := rule.matchListAndMode(api, answers, onList)

		// Owner rules include change outputs.
		onOutput := api.Mul(ruleEnabled[ruleIndex], api.Add(onOwner, onAsset))
		for outputIndex := range slots.outputs {
			var matches [NAnswers]frontend.Variable
			for answerIndex := range answers {
				sameMember := api.Select(onAsset, eqOutputAsset[answerIndex][outputIndex], eqOutputOwner[answerIndex][outputIndex])
				matches[answerIndex] = api.Mul(listAndModeMatches[answerIndex], sameMember)
			}
			applies := api.Mul(onOutput, api.Select(onAsset, liveAsset[outputIndex], liveOwner[outputIndex]))
			covered := api.Select(isInline, limits[outputIndex].found, anyOf(api, matches[:]))
			amounts := guardAmounts{
				subjectTotal:    api.Select(onAsset, totals[outputIndex].byAsset, totals[outputIndex].byOwner),
				ownerAssetTotal: totals[outputIndex].byOwnerAndAsset,
				assetLimit:      limits[outputIndex],
			}
			exempt := rule.amountExemption(api, amounts)
			// A per-asset guard requires a configured asset limit.
			shared.AssertWhen(api, api.Mul(applies, hasPerAssetGuard), limits[outputIndex].found)
			shared.AssertWhen(api, applies, api.Or(covered, exempt))
		}

		// Sender rules have no amount exemption.
		onInput := api.Mul(ruleEnabled[ruleIndex], onSender)
		for inputIndex := range slots.inputs {
			var matches [NAnswers]frontend.Variable
			for answerIndex := range answers {
				matches[answerIndex] = api.Mul(listAndModeMatches[answerIndex], eqSender[answerIndex][inputIndex])
			}
			applies := api.Mul(onInput, liveSender[inputIndex])
			covered := anyOf(api, matches[:])
			shared.AssertWhen(api, applies, covered)
		}
	}
}

func anyOf(api frontend.API, terms []frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for _, term := range terms {
		result = api.Or(result, term)
	}
	return result
}

func nonZero(api frontend.API, value frontend.Variable) frontend.Variable {
	return api.Sub(1, api.IsZero(value))
}
