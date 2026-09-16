package custom_ring

import (
	"encoding/json"
	"fmt"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover/common"
)

type DelegatePolicyParameters struct {
	Policy PolicyParameters
}

type delegatePolicyJSON struct {
	CircuitType string          `json:"circuitType"`
	Policy      json.RawMessage `json:"policy"`
}

func (p *DelegatePolicyParameters) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(&p.Policy)
	if err != nil {
		return nil, err
	}
	return json.Marshal(delegatePolicyJSON{
		CircuitType: string(common.CustomRingDelegatePolicyCircuitType),
		Policy:      raw,
	})
}

func (p *DelegatePolicyParameters) UnmarshalJSON(data []byte) error {
	var raw delegatePolicyJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	rail := string(common.CustomRingDelegatePolicyCircuitType)
	if raw.CircuitType != rail {
		return fmt.Errorf("%s: unexpected circuitType %q", rail, raw.CircuitType)
	}
	if err := json.Unmarshal(raw.Policy, &p.Policy); err != nil {
		return err
	}
	if p.Policy.WindowIndex != 0 || p.Policy.ApprovalRequired {
		return fmt.Errorf("%s: windowIndex and approvalRequired must be zero", rail)
	}
	return nil
}

func (p *DelegatePolicyParameters) CreateWitness() (*policy.CustomRingDelegatePolicyCircuit, error) {
	base, err := p.Policy.CreateWitness()
	if err != nil {
		return nil, err
	}
	return &policy.CustomRingDelegatePolicyCircuit{Policy: *base}, nil
}
