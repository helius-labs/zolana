package indexed

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/prover/common"
	ring "zolana/prover/prover/custom_ring"
)

func policyCircuit(circuit common.CircuitType) bool {
	switch circuit {
	case common.CustomRingPolicyCircuitType, common.CustomRingCompressedPolicyCircuitType, common.CustomRingDelegatePolicyCircuitType:
		return true
	default:
		return false
	}
}

type policyTarget struct {
	fact                       *ring.ListFact
	state, exclusion           []*big.Int
	stateIndex, exclusionIndex *big.Int
}

type resolvedPolicy struct {
	base    *ring.PolicyParameters
	wrapped json.Marshaler
	targets []policyTarget
	slots   []common.TreeSlotParams
}

func (p *resolvedPolicy) MarshalJSON() ([]byte, error) {
	for _, target := range p.targets {
		copy(target.fact.StatePathElements[:], target.state)
		copy(target.fact.NfPathElements[:], target.exclusion)
		target.fact.StatePathIndex = target.stateIndex.Uint64()
		target.fact.NfPathIndex = target.exclusionIndex.Uint64()
	}
	for i, slot := range p.slots {
		p.base.TreeSlots[i] = ring.TreeSlot{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot}
	}
	return p.wrapped.MarshalJSON()
}

func decodePolicy(request Request) (*preparedProof, error) {
	var outer map[string]json.RawMessage
	if json.Unmarshal(request.Prepared, &outer) != nil {
		return nil, fmt.Errorf("invalid prepared policy")
	}
	var base map[string]json.RawMessage
	if request.CircuitType == common.CustomRingPolicyCircuitType {
		base = outer
	} else {
		if json.Unmarshal(outer["policy"], &base) != nil {
			return nil, fmt.Errorf("missing prepared policy")
		}
	}
	if base["treeSlots"] != nil || base["publicInputHash"] != nil {
		return nil, fmt.Errorf("prepared policy contains resolved roots")
	}
	var facts []map[string]json.RawMessage
	if json.Unmarshal(base["answers"], &facts) != nil || len(facts) != 10 || len(request.Inputs) != len(facts) {
		return nil, fmt.Errorf("invalid prepared fact count")
	}
	for _, fact := range facts {
		if fact == nil {
			return nil, fmt.Errorf("invalid prepared fact")
		}
		for field, height := range map[string]int{"nfPathElements": 40, "statePathElements": 32} {
			if fact[field] != nil {
				return nil, fmt.Errorf("prepared policy contains paths")
			}
			nodes := make([]string, height)
			for i := range nodes {
				nodes[i] = common.ToHex(new(big.Int))
			}
			fact[field], _ = json.Marshal(nodes)
		}
		for _, name := range []string{"nfPathIndex", "statePathIndex", "low", "next"} {
			if fact[name] != nil {
				return nil, fmt.Errorf("prepared policy contains proof data")
			}
		}
		fact["nfPathIndex"], fact["statePathIndex"] = json.RawMessage("0"), json.RawMessage("0")
		fact["low"], _ = json.Marshal(common.ToHex(new(big.Int)))
		fact["next"] = fact["low"]
	}
	if err := prepareRegistry(base, request.Registry); err != nil {
		return nil, err
	}
	slots := make([]common.TreeSlotParams, len(request.Trees))
	for i, tree := range request.Trees {
		fallback := tree.Fallback
		if fallback == nil || fallback.Tree != tree.Address || fallback.ID != tree.ID || fallback.UtxoRootIndex >= 500 || fallback.NullifierRootIndex >= 100 {
			return nil, fmt.Errorf("invalid policy fallback roots")
		}
		state, err := common.FeFromHex(fallback.UtxoRoot)
		if err != nil || state.Sign() == 0 {
			return nil, fmt.Errorf("invalid policy state root")
		}
		exclusion, err := common.FeFromHex(fallback.NullifierRoot)
		if err != nil {
			return nil, err
		}
		if _, err := hashField(state); err != nil {
			return nil, err
		}
		if _, err := hashField(exclusion); err != nil {
			return nil, err
		}
		slots[i] = common.TreeSlotParams{ID: new(big.Int).SetUint64(uint64(tree.ID)), UtxoRoot: state, NullifierRoot: exclusion}
	}
	base["treeSlots"], _ = json.Marshal(common.TreeSlotsToJSON(slots))
	base["publicInputHash"], _ = json.Marshal(common.ToHex(new(big.Int)))
	base["answers"], _ = json.Marshal(facts)
	if request.CircuitType != common.CustomRingPolicyCircuitType {
		outer["policy"], _ = json.Marshal(base)
	}
	data, err := json.Marshal(outer)
	if err != nil {
		return nil, err
	}
	p := &resolvedPolicy{}
	switch request.CircuitType {
	case common.CustomRingPolicyCircuitType:
		value := &ring.PolicyParameters{}
		if err = json.Unmarshal(data, value); err != nil {
			return nil, err
		}
		p.base, p.wrapped = value, value
	case common.CustomRingCompressedPolicyCircuitType:
		value := &ring.CompressedPolicyParameters{}
		if err = json.Unmarshal(data, value); err != nil {
			return nil, err
		}
		p.base, p.wrapped = &value.Base, value
	case common.CustomRingDelegatePolicyCircuitType:
		value := &ring.DelegatePolicyParameters{}
		if err = json.Unmarshal(data, value); err != nil {
			return nil, err
		}
		p.base, p.wrapped = &value.Policy, value
	}
	p.targets = make([]policyTarget, len(facts))
	inputs := make([]inputTarget, len(facts))
	for i := range p.targets {
		fact, lookup := &p.base.ListFacts[i], request.Inputs[i]
		if int(lookup.TreeSlot) >= len(request.Trees) || fact.TreeSlot != lookup.TreeSlot || fact.Enabled != (lookup.Nullifier != nil) || (fact.Enabled && (fact.AbsentBranch == 2) != (lookup.Commitment != nil)) || (!fact.Enabled && lookup.Commitment != nil) {
			return nil, fmt.Errorf("policy lookup mismatch")
		}
		target := &p.targets[i]
		*target = policyTarget{fact: fact, stateIndex: new(big.Int), exclusionIndex: new(big.Int)}
		nullifier := new(big.Int)
		if lookup.Nullifier != nil {
			nullifier, err = lookup.Nullifier.field()
			if err != nil {
				return nil, err
			}
		}
		inputs[i] = inputTarget{slot: big.NewInt(int64(lookup.TreeSlot)), nullifier: nullifier, cached: lookup.Commitment == nil, disabled: !fact.Enabled,
			state: &target.state, exclusion: &target.exclusion, stateIndex: &target.stateIndex, exclusionIndex: &target.exclusionIndex, low: &fact.Low, high: &fact.Next}
	}
	return &preparedProof{value: p, inputs: inputs, slots: &p.slots, hash: &p.base.PublicInputHash, policy: true, registry: p}, nil
}
