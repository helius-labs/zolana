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
	if shape, ok := common.ParseRingPolicyShape(circuit); ok {
		return !shape.Subtree
	}
	switch circuit {
	case common.CustomRingPolicyCircuitType, common.CustomRingDelegatePolicyCircuitType:
		return true
	default:
		return false
	}
}

// decodePolicy reads a policy request without the roots, member openings and ciphertext hashes the indexer supplies.
func decodePolicy(request Request) (*preparedProof, error) {
	var value any
	var p *ring.PolicyParams
	shape, _ := common.ParseRingPolicyShape(request.CircuitType)
	if request.CircuitType == common.CustomRingDelegatePolicyCircuitType || shape.Delegate {
		wrapper := &ring.DelegatePolicyParams{}
		value, p = wrapper, &wrapper.Policy
	} else {
		p = &ring.PolicyParams{}
		value = p
	}
	if err := ring.Unmarshal(request.Prepared, value); err != nil {
		return nil, fmt.Errorf("invalid prepared policy: %w", err)
	}
	if p.TreeSlots != nil || p.PublicInputHash.Int != nil {
		return nil, fmt.Errorf("prepared policy contains resolved roots")
	}
	if len(request.Inputs) != 0 {
		return nil, fmt.Errorf("policy requests carry no input lookups")
	}
	if err := prepareRegistries(p, request); err != nil {
		return nil, err
	}
	for _, tree := range request.Trees {
		fallback := tree.Fallback
		if fallback == nil || fallback.Tree != tree.Address || fallback.ID != tree.ID || fallback.UtxoRootIndex >= 500 || fallback.NullifierRootIndex >= 100 {
			return nil, fmt.Errorf("invalid policy fallback roots")
		}
		state, stateErr := common.FeFromHex(fallback.UtxoRoot)
		exclusion, exclusionErr := common.FeFromHex(fallback.NullifierRoot)
		if stateErr != nil || exclusionErr != nil || state.Sign() == 0 || !canonical(state) || !canonical(exclusion) {
			return nil, fmt.Errorf("invalid policy fallback roots")
		}
	}
	p.PublicInputHash = ring.Field{Int: new(big.Int)}
	p.TreeSlots = make(ring.TreeSlots, shared.InputTrees)
	for i := range p.TreeSlots {
		p.TreeSlots[i] = common.TreeSlotParams{ID: new(big.Int), UtxoRoot: new(big.Int), NullifierRoot: new(big.Int)}
	}
	if _, err := ring.Assign(request.CircuitType, value); err != nil {
		return nil, fmt.Errorf("invalid prepared policy: %w", err)
	}
	return &preparedProof{value: value, slots: (*[]common.TreeSlotParams)(&p.TreeSlots), hash: &p.PublicInputHash.Int, policy: true, registry: p}, nil
}

func canonical(value *big.Int) bool {
	_, err := hashField(value)
	return err == nil
}

func hashFields(hashes []Hash) []ring.Field {
	out := make([]ring.Field, len(hashes))
	for i, hash := range hashes {
		out[i] = ring.Field{Int: new(big.Int).SetBytes(hash[:])}
	}
	return out
}

// liveSubjects lists input owners, output owners, then output assets used by asset rules.
func liveSubjects(p *ring.PolicyParams) []int {
	var live []int
	for i, input := range p.Inputs {
		if i < int(p.NIn) && input.Domain.Int != nil && input.Domain.Cmp(big.NewInt(shared.UtxoDomain)) == 0 {
			live = append(live, i)
		}
	}
	assetRules := false
	for i, rule := range p.Rules {
		if i < int(p.PolicyLen) && rule.Int != nil && rule.Uint64()&255 == policy.SubjectAsset {
			assetRules = true
		}
	}
	for o, output := range p.Outputs {
		if o < int(p.NOut) && output.Domain.Int != nil && output.Domain.Cmp(big.NewInt(shared.UtxoDomain)) == 0 {
			live = append(live, len(p.Inputs)+o)
			if assetRules && output.Asset.Int != nil && output.Asset.Sign() != 0 {
				live = append(live, len(p.Inputs)+len(p.Outputs)+o)
			}
		}
	}
	return live
}

func subjectOpening(p *ring.PolicyParams, slot int) *ring.Opening {
	if slot < len(p.Inputs) {
		return &p.Inputs[slot]
	}
	return &p.Outputs[(slot-len(p.Inputs))%len(p.Outputs)].Opening
}
