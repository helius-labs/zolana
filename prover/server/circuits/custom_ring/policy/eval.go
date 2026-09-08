package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/spp_transaction/shared"
)

// evaluate requires every applicable rule to be satisfied or exempt.
func (c *CustomRingPolicyCircuit) evaluate(
	api frontend.API,
	txContext transactionContext,
	listFacts [NListFacts]listFact,
	ruleEnabled [NRules]frontend.Variable,
	inlineEnabled [NInlineAssets]frontend.Variable,
) {
	// 1. Prepare list fact comparisons for reuse across rules and
	// transaction slots.
	var eqOutputOwner, eqOutputAsset [NListFacts][NOutputs]frontend.Variable
	var eqSender [NListFacts][NInputs]frontend.Variable
	var onList [NListFacts][NSources]frontend.Variable
	for factIndex, fact := range listFacts {
		for outputIndex, output := range txContext.outputs {
			eqOutputOwner[factIndex][outputIndex] = api.IsZero(api.Sub(fact.member, output.ownerPkHash))
			eqOutputAsset[factIndex][outputIndex] = api.IsZero(api.Sub(fact.member, output.asset))
		}
		for inputIndex, input := range txContext.inputs {
			eqSender[factIndex][inputIndex] = api.IsZero(api.Sub(fact.member, input.ownerPkHash))
		}
		for listIndex := range onList[factIndex] {
			onList[factIndex][listIndex] = api.IsZero(api.Sub(fact.listId, listIndex+1))
		}
	}

	// 2. Exclude zero subjects and non-UTXO slots from rule obligations.
	var liveOwner, liveAsset [NOutputs]frontend.Variable
	for i, output := range txContext.outputs {
		liveOwner[i] = api.Mul(output.live, nonZero(api, output.ownerPkHash))
		liveAsset[i] = api.Mul(output.live, nonZero(api, output.asset))
	}
	var liveSender [NInputs]frontend.Variable
	for i, input := range txContext.inputs {
		liveSender[i] = api.Mul(input.live, nonZero(api, input.ownerPkHash))
	}

	// 3. Prepare shared inline matches and grouped output amounts.
	limits := c.matchInlineAssets(api, txContext.outputs, inlineEnabled)
	totals := sumOutputs(api, txContext.outputs, liveOwner, liveAsset)

	// 4. Match each rule's list and mode alternatives.
	for ruleIndex, rule := range c.Rules {
		isInline := api.IsZero(rule.ListMask)
		hasPerAssetGuard := api.IsZero(api.Sub(rule.GuardTag, GuardAboveAmountByAsset))
		onOwner := api.IsZero(api.Sub(rule.Subject, SubjectOutputOwner))
		onAsset := api.IsZero(api.Sub(rule.Subject, SubjectAsset))
		onSender := api.IsZero(api.Sub(rule.Subject, SubjectSender))
		readMatchesRule := rule.matchListAndMode(api, listFacts, onList)

		// 5. Check list conditions for each output subject, including
		// change.
		onOutput := api.Mul(ruleEnabled[ruleIndex], api.Add(onOwner, onAsset))
		for outputIndex := range txContext.outputs {
			var matches [NListFacts]frontend.Variable
			for factIndex := range listFacts {
				sameMember := api.Select(onAsset, eqOutputAsset[factIndex][outputIndex], eqOutputOwner[factIndex][outputIndex])
				matches[factIndex] = api.Mul(readMatchesRule[factIndex], sameMember)
			}
			instanceEnabled := api.Mul(onOutput, api.Select(onAsset, liveAsset[outputIndex], liveOwner[outputIndex]))
			satisfied := api.Select(isInline, limits[outputIndex].found, anyOf(api, matches[:]))

			// 6. Check the amount exemption for the output's group.
			amounts := guardAmounts{
				subjectOutputTotal: api.Select(onAsset, totals[outputIndex].byAsset, totals[outputIndex].byOwner),
				ownerAssetTotal:    totals[outputIndex].byOwnerAndAsset,
				assetLimit:         limits[outputIndex],
			}
			exempt := rule.amountExemption(api, amounts)

			// 7. Require per-asset limits even when the list
			// condition is satisfied.
			shared.AssertWhen(api, api.Mul(instanceEnabled, hasPerAssetGuard), limits[outputIndex].found)

			// 8. Require the list condition or an amount exemption.
			shared.AssertWhen(api, instanceEnabled, api.Or(satisfied, exempt))
		}

		// 9. Require a matching list fact for each sender without
		// amount exemptions.
		onInput := api.Mul(ruleEnabled[ruleIndex], onSender)
		for inputIndex := range txContext.inputs {
			var matches [NListFacts]frontend.Variable
			for factIndex := range listFacts {
				matches[factIndex] = api.Mul(readMatchesRule[factIndex], eqSender[factIndex][inputIndex])
			}
			instanceEnabled := api.Mul(onInput, liveSender[inputIndex])
			satisfied := anyOf(api, matches[:])
			shared.AssertWhen(api, instanceEnabled, satisfied)
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
