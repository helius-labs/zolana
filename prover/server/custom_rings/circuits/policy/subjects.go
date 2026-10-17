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
func (c *CustomRingPolicyCircuit) resolveSubjects(api frontend.API, tx transaction, checked checkedPolicy) []subjectView {
	sources := checked.sources
	inputs, outputs, ownOpenings, foreignOpenings := c.wires()
	subjects := make([]subjectView, len(ownOpenings))
	var ownBatch, foreignBatch *registry.SubtreeBatch
	if c.RegistryWitness != nil {
		ownBatch = registry.NewSparseSubtreeBatch(api, c.MemberRegistryRoot, &c.RegistryWitness[0])
		foreignBatch = registry.NewSparseSubtreeBatch(api, c.ForeignRoot, &c.RegistryWitness[1])
	} else if c.RegistrySubtreeDepth != 0 {
		ownBatch = registry.NewSubtreeBatch(c.RegistrySubtreeDepth, c.MemberRegistryRoot)
		foreignBatch = registry.NewSubtreeBatch(c.RegistrySubtreeDepth, c.ForeignRoot)
	}
	resolve := func(o registry.MemberOpening, active, root, member frontend.Variable, batch *registry.SubtreeBatch) (frontend.Variable, frontend.Variable) {
		if batch != nil {
			return batch.Resolve(api, o, active, member)
		}
		if c.specialized() {
			return o.ResolveCompact(api, active, root, member)
		}
		return o.Resolve(api, active, root, member)
	}
	for index, slot := range tx.slots() {
		s := index
		if index >= len(tx.inputs) {
			s = len(inputs) + index - len(tx.inputs)
		}
		own, escrowKey := resolve(ownOpenings[s], slot.utxo, c.MemberRegistryRoot, slot.ownerPkHash, ownBatch)
		foreign, _ := resolve(foreignOpenings[s], api.Mul(slot.utxo, sources.anyForeign), c.ForeignRoot, slot.ownerPkHash, foreignBatch)
		ownBits, foreignBits := api.ToBinary(own, registry.ListBits), api.ToBinary(foreign, registry.ListBits)
		subjects[s] = subjectView{present: ownOpenings[s].Present, escrowKey: escrowKey}
		for i := range subjects[s].onList {
			subjects[s].onList[i] = api.Select(sources.foreign[i], foreignBits[i], ownBits[i])
		}
	}
	assetRules := frontend.Variable(0)
	rules := base.SelectCount(api, c.PolicyLen, 0, NRules+1)
	for i, packed := range c.Rules {
		var rule ruleFields
		if c.specialized() {
			rule = checked.rules[i]
		} else {
			rule = decodeRule(api, packed)
		}
		active := rules.Active[i]
		assetRules = api.Or(assetRules, api.Mul(active, rule.onAsset))
	}
	for o, slot := range tx.outputs {
		s := len(inputs) + len(outputs) + o
		active := api.Mul(slot.utxo, assetRules, base.NonZero(api, slot.asset))
		own, _ := resolve(ownOpenings[s], active, c.MemberRegistryRoot, slot.asset, ownBatch)
		foreign, _ := resolve(foreignOpenings[s], api.Mul(active, sources.anyForeign), c.ForeignRoot, slot.asset, foreignBatch)
		ownBits, foreignBits := api.ToBinary(own, registry.ListBits), api.ToBinary(foreign, registry.ListBits)
		for i := range subjects[s].onList {
			subjects[s].onList[i] = api.Select(sources.foreign[i], foreignBits[i], ownBits[i])
		}
	}
	if ownBatch != nil {
		ownBatch.Check(api)
		foreignBatch.Check(api)
	}
	return subjects
}

// constrainEscrow requires every live output owner's record to escrow the key the output uses.
func (c *CustomRingPolicyCircuit) constrainEscrow(api frontend.API, tx transaction, subjects []subjectView) {
	api.AssertIsBoolean(c.KeyEscrow)
	for o, output := range tx.outputs {
		inputs, outputs, _, _ := c.wires()
		subject := subjects[len(inputs)+o]
		escrowed := api.Mul(output.utxo, c.KeyEscrow)
		shared.AssertWhen(api, escrowed, subject.present)
		key := gadget.PoseidonHash(api, []frontend.Variable{output.nullifierPk, outputs[o].CtHash})
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: subject.escrowKey, B: key})
	}
}
