package custom_ring

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/deposit"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// RingCircuit pairs a ring statement with the request that assigns it.
type RingCircuit struct {
	Type    common.CircuitType
	Circuit func() frontend.Circuit
	params  func() any
}

func ring[P any, C any, PC interface {
	*C
	frontend.Circuit
}](circuitType common.CircuitType) RingCircuit {
	return RingCircuit{
		Type:    circuitType,
		Circuit: func() frontend.Circuit { return PC(new(C)) },
		params:  func() any { return new(P) },
	}
}

var RingCircuits = []RingCircuit{
	ring[PolicyParams, policy.CustomRingPolicyCircuit](common.CustomRingPolicyCircuitType),
	ring[BaseParams, base.CustomRingBaseCircuit](common.CustomRingBaseCircuitType),
	ring[BaseParams, base.CustomRingConfidentialCircuit](common.CustomRingConfidentialCircuitType),
	ring[DelegatePolicyParams, policy.CustomRingDelegatePolicyCircuit](common.CustomRingDelegatePolicyCircuitType),
	ring[KeyRegisterParams, policy.KeyRegisterCircuit](common.CustomRingKeyRegisterCircuitType),
	ring[DepositParams, deposit.CustomRingDepositCircuit](common.CustomRingDepositCircuitType),
	ring[UpdateMembersParams, registry.UpdateMembersCircuit](common.CustomRingUpdateMembersCircuitType),
}

func Ring(circuitType common.CircuitType) (RingCircuit, error) {
	for _, ring := range RingCircuits {
		if ring.Type == circuitType {
			return ring, nil
		}
	}
	return RingCircuit{}, fmt.Errorf("unknown custom-ring circuit type: %s", circuitType)
}

// Decode turns a request into its circuit assignment.
func Decode(circuitType common.CircuitType, payload []byte) (frontend.Circuit, error) {
	ring, err := Ring(circuitType)
	if err != nil {
		return nil, err
	}
	params := ring.params()
	if err := Unmarshal(payload, params); err != nil {
		return nil, err
	}
	if circuitType == common.CustomRingConfidentialCircuitType && params.(*BaseParams).Anonymous {
		return nil, fmt.Errorf("confidential audit circuit cannot prove anonymous disclosure")
	}
	return Assign(circuitType, params)
}

// Assign fails for a request that leaves a circuit value unset.
func Assign(circuitType common.CircuitType, params any) (frontend.Circuit, error) {
	ring, err := Ring(circuitType)
	if err != nil {
		return nil, err
	}
	assignment := ring.Circuit()
	return assignment, assign(assignment, params)
}

func Prove(ps *common.RingProofSystem, assignment frontend.Circuit, prover common.Prover) (*common.Proof, error) {
	proof, err := prover.Run(ps.ConstraintSystem, ps.ProvingKey, func() (frontend.Circuit, error) { return assignment, nil })
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof, ProvingKeySha256: ps.ProvingKeySha256}, nil
}

func (r RingCircuit) R1CS() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, r.Circuit(), frontend.WithCompressThreshold(300))
}

func (r RingCircuit) Setup() (*common.RingProofSystem, error) {
	ccs, err := r.R1CS()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return &common.RingProofSystem{CircuitType: r.Type, ProvingKey: pk, VerifyingKey: vk, ConstraintSystem: ccs}, nil
}

// Convert wraps an existing gnark key pair, written by a setup, with the compiled circuit.
func (r RingCircuit) Convert(pkPath, vkPath string) (*common.RingProofSystem, error) {
	ccs, err := r.R1CS()
	if err != nil {
		return nil, err
	}
	pk, err := common.LoadProvingKey(pkPath)
	if err != nil {
		return nil, err
	}
	vk, err := common.LoadVerifyingKey(vkPath)
	if err != nil {
		return nil, err
	}
	return &common.RingProofSystem{CircuitType: r.Type, ProvingKey: pk, VerifyingKey: vk, ConstraintSystem: ccs}, nil
}
