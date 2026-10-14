package indexed

import (
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	ring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
)

func policyCircuit(circuit common.CircuitType) bool {
	switch circuit {
	case common.CustomRingPolicyCircuitType, common.CustomRingCompressedPolicyCircuitType, common.CustomRingDelegatePolicyCircuitType:
		return true
	default:
		return false
	}
}

// decodePolicy reads a policy request without the roots, paths and output keys the indexer supplies.
func decodePolicy(request Request) (*preparedProof, error) {
	var value any
	var p *ring.PolicyParams
	switch request.CircuitType {
	case common.CustomRingPolicyCircuitType:
		p = &ring.PolicyParams{}
		value = p
	case common.CustomRingDelegatePolicyCircuitType:
		wrapper := &ring.DelegatePolicyParams{}
		value, p = wrapper, &wrapper.Policy
	default:
		wrapper := &ring.CompressedPolicyParams{}
		value, p = wrapper, &wrapper.Policy
	}
	if err := ring.Unmarshal(request.Prepared, value); err != nil {
		return nil, fmt.Errorf("invalid prepared policy: %w", err)
	}
	if p.TreeSlots != nil || p.PublicInputHash.Int != nil {
		return nil, fmt.Errorf("prepared policy contains resolved roots")
	}
	if len(p.ListFacts) != policy.NListFacts || len(request.Inputs) != len(p.ListFacts) {
		return nil, fmt.Errorf("invalid prepared fact count")
	}
	if err := prepareRegistry(p, request.Registry); err != nil {
		return nil, err
	}
	for _, tree := range request.Trees {
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
	}
	p.PublicInputHash = ring.Field{Int: new(big.Int)}
	p.TreeSlots = make(ring.TreeSlots, shared.InputTrees)
	for i := range p.TreeSlots {
		p.TreeSlots[i] = common.TreeSlotParams{ID: new(big.Int), UtxoRoot: new(big.Int), NullifierRoot: new(big.Int)}
	}
	inputs := make([]inputTarget, len(p.ListFacts))
	for i := range p.ListFacts {
		fact, lookup := &p.ListFacts[i], request.Inputs[i]
		if fact.NullifierLowPathElements != nil || fact.StatePathElements != nil || fact.NullifierLowPathIndex != 0 || fact.StatePathIndex != 0 || fact.NullifierLowValue.Int != nil || fact.NullifierNextValue.Int != nil {
			return nil, fmt.Errorf("prepared policy contains proof data")
		}
		cleared := fact.AbsentBranch == policy.AbsentBranchCleared
		if int(lookup.TreeSlot) >= len(request.Trees) || fact.TreeSlot != lookup.TreeSlot || fact.Enabled != (lookup.Nullifier != nil) || (fact.Enabled && cleared != (lookup.Commitment != nil)) || (!fact.Enabled && lookup.Commitment != nil) {
			return nil, fmt.Errorf("policy lookup mismatch")
		}
		fact.NullifierLowPathElements, fact.StatePathElements = zeroFields(shared.NullifierTreeHeight), zeroFields(shared.StateTreeHeight)
		fact.NullifierLowValue, fact.NullifierNextValue = ring.Field{Int: new(big.Int)}, ring.Field{Int: new(big.Int)}
		nullifier := new(big.Int)
		if lookup.Nullifier != nil {
			var err error
			if nullifier, err = lookup.Nullifier.field(); err != nil {
				return nil, err
			}
		}
		inputs[i] = inputTarget{slot: big.NewInt(int64(lookup.TreeSlot)), nullifier: nullifier, cached: lookup.Commitment == nil, disabled: !fact.Enabled,
			fill: func(state *stateProof, exclusion nullifierProof) {
				if state != nil {
					fact.StatePathElements, fact.StatePathIndex = hashFields(state.Path), state.LeafIndex
				}
				fact.NullifierLowPathElements, fact.NullifierLowPathIndex = hashFields(exclusion.Path), exclusion.LowElementIndex
				fact.NullifierLowValue = ring.Field{Int: new(big.Int).SetBytes(exclusion.LowElement[:])}
				fact.NullifierNextValue = ring.Field{Int: new(big.Int).SetBytes(exclusion.HighElement[:])}
			}}
	}
	circuit, err := ring.Ring(request.CircuitType)
	if err != nil {
		return nil, err
	}
	if _, err := circuit.Assign(value); err != nil {
		return nil, fmt.Errorf("invalid prepared policy: %w", err)
	}
	return &preparedProof{value: value, inputs: inputs, slots: (*[]common.TreeSlotParams)(&p.TreeSlots), hash: &p.PublicInputHash.Int, policy: true, registry: p}, nil
}

func zeroFields(n int) []ring.Field {
	return hashFields(make([]Hash, n))
}

func hashFields(hashes []Hash) []ring.Field {
	out := make([]ring.Field, len(hashes))
	for i, hash := range hashes {
		out[i] = ring.Field{Int: new(big.Int).SetBytes(hash[:])}
	}
	return out
}
