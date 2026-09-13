package custom_ring

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover/common"
)

func R1CSDelegatePolicy() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder,
		&policy.CustomRingDelegatePolicyCircuit{}, frontend.WithCompressThreshold(300))
}

func SetupDelegatePolicy() (*common.RingProofSystem, error) {
	ccs, err := R1CSDelegatePolicy()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.RingProofSystem{CircuitType: common.CustomRingDelegatePolicyCircuitType,
		ProvingKey: pk, VerifyingKey: vk, ConstraintSystem: ccs}, nil
}

type ConvertDelegatePolicy struct{ ProvingKeyPath, VerifyingKeyPath string }

func (c ConvertDelegatePolicy) Run() (*common.RingProofSystem, error) {
	ccs, err := R1CSDelegatePolicy()
	if err != nil {
		return nil, err
	}
	pk, vk := groth16.NewProvingKey(ecc.BN254), groth16.NewVerifyingKey(ecc.BN254)
	if err := readKey(c.ProvingKeyPath, pk); err != nil {
		return nil, err
	}
	if err := readKey(c.VerifyingKeyPath, vk); err != nil {
		return nil, err
	}
	return &common.RingProofSystem{CircuitType: common.CustomRingDelegatePolicyCircuitType,
		ProvingKey: pk, VerifyingKey: vk, ConstraintSystem: ccs}, nil
}

type DelegatePolicyParameters struct{ Policy PolicyParameters }
type delegatePolicyJSON struct {
	CircuitType string          `json:"circuitType"`
	Policy      json.RawMessage `json:"policy"`
}

func (p *DelegatePolicyParameters) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(&p.Policy)
	if err != nil {
		return nil, err
	}
	return json.Marshal(delegatePolicyJSON{string(common.CustomRingDelegatePolicyCircuitType), raw})
}
func (p *DelegatePolicyParameters) UnmarshalJSON(data []byte) error {
	var raw delegatePolicyJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.CustomRingDelegatePolicyCircuitType) {
		return fmt.Errorf("unexpected delegate circuit type %q", raw.CircuitType)
	}
	if err := json.Unmarshal(raw.Policy, &p.Policy); err != nil {
		return err
	}
	if p.Policy.WindowIndex != 0 || p.Policy.ApprovalRequired {
		return fmt.Errorf("delegate policy window and approval must be zero")
	}
	return nil
}
func ProveDelegatePolicy(ps *common.RingProofSystem, params *DelegatePolicyParameters) (*common.Proof, error) {
	base, err := params.Policy.CreateWitness()
	if err != nil {
		return nil, err
	}
	assignment := &policy.CustomRingDelegatePolicyCircuit{Policy: *base}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("delegate witness creation failed (%w)", err)
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("delegate proving failed (%w)", err)
	}
	return &common.Proof{Proof: proof}, nil
}
