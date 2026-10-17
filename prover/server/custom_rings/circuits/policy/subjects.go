package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

// subjectView is one slot's owner as the registries record it.
type subjectView struct {
	// onList[i] is set when the owner is on list i+1, read from the registry that serves the list.
	onList [NSources]frontend.Variable
	// present and escrowKey come from the ring's own registry.
	present, escrowKey frontend.Variable
}

// resolveSubjects opens every live UTXO slot's owner in the ring registry, and in the curator
// registry when the sources name one. Other slots leave their openings unread.
func (c *CustomRingPolicyCircuit) resolveSubjects(api frontend.API, tx transaction, sources sourcesView) [NSubjects]subjectView {
	var subjects [NSubjects]subjectView
	for s, slot := range tx.slots() {
		own, escrowKey := c.Subjects[s].Resolve(api, slot.utxo, c.MemberRegistryRoot, slot.ownerPkHash)
		foreign, _ := c.ForeignSubjects[s].Resolve(api, api.Mul(slot.utxo, sources.anyForeign), c.ForeignRoot, slot.ownerPkHash)
		ownBits, foreignBits := api.ToBinary(own, registry.ListBits), api.ToBinary(foreign, registry.ListBits)
		subjects[s] = subjectView{present: c.Subjects[s].Present, escrowKey: escrowKey}
		for i := range subjects[s].onList {
			subjects[s].onList[i] = api.Select(sources.foreign[i], foreignBits[i], ownBits[i])
		}
	}
	assetRules := frontend.Variable(0)
	rules := base.SelectCount(api, c.PolicyLen, 0, NRules+1)
	for i, packed := range c.Rules {
		rule := decodeRule(api, packed)
		active := rules.Active[i]
		assetRules = api.Or(assetRules, api.Mul(active, rule.onAsset))
	}
	for o, slot := range tx.outputs {
		s := NInputs + NOutputs + o
		active := api.Mul(slot.utxo, assetRules, base.NonZero(api, slot.asset))
		own, _ := c.Subjects[s].Resolve(api, active, c.MemberRegistryRoot, slot.asset)
		foreign, _ := c.ForeignSubjects[s].Resolve(api, api.Mul(active, sources.anyForeign), c.ForeignRoot, slot.asset)
		ownBits, foreignBits := api.ToBinary(own, registry.ListBits), api.ToBinary(foreign, registry.ListBits)
		for i := range subjects[s].onList {
			subjects[s].onList[i] = api.Select(sources.foreign[i], foreignBits[i], ownBits[i])
		}
	}
	return subjects
}

// constrainEscrow requires every live output owner's record to escrow the key the output uses.
func (c *CustomRingPolicyCircuit) constrainEscrow(api frontend.API, tx transaction, subjects [NSubjects]subjectView) {
	api.AssertIsBoolean(c.KeyEscrow)
	for o, output := range tx.outputs {
		subject := subjects[NInputs+o]
		escrowed := api.Mul(output.utxo, c.KeyEscrow)
		shared.AssertWhen(api, escrowed, subject.present)
		key := gadget.PoseidonHash(api, []frontend.Variable{output.nullifierPk, c.Outputs[o].CtHash})
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: subject.escrowKey, B: key})
	}
}
