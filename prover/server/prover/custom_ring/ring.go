package custom_ring

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/deposit"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/merge"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// RingCircuit pairs a ring statement with the request that assigns it.
type RingCircuit struct {
	Type    common.CircuitType
	circuit func() (frontend.Circuit, error)
	params  func() any
}

var RingCircuits = func() []RingCircuit {
	circuits := make([]RingCircuit, len(common.RingKeys))
	for i, key := range common.RingKeys {
		circuits[i] = newRingCircuit(key)
	}
	return circuits
}()

func newRingCircuit(key common.RingKey) RingCircuit {
	r := RingCircuit{Type: key.Circuit}
	switch key.Family {
	case common.RingPackedAudit:
		r.circuit = sized(base.NewPackedAuditCircuit, key.Outputs)
		r.params = newParams[PackedAuditParams]
	case common.RingDeliveredAudit:
		r.circuit = sized(base.NewDeliveredAuditCircuit, key.Outputs)
		r.params = newParams[DeliveredAuditParams]
	case common.RingAnonymousAudit, common.RingAnonymousEntryAudit:
		r.circuit = sized(base.NewAnonymousAuditCircuit, anonymousShape(key))
		r.params = newParams[AnonymousAuditParams]
	case common.RingMemberPolicy:
		r.circuit = sized(policy.NewMemberPolicyCircuit, key.Outputs)
		r.params = newParams[MemberPolicyParams]
	case common.RingDelegatePolicy:
		r.circuit = sized(policy.NewDelegatePolicyCircuit, shared.Shape{NInputs: key.Inputs, NOutputs: key.Outputs})
		r.params = newParams[DelegatePolicyParams]
	case common.RingApplyRecords:
		r.circuit = func() (frontend.Circuit, error) { return registry.NewApplyRecordsCircuit(key.Inputs), nil }
		r.params = newParams[ApplyRecordsParams]
	case common.RingRegisterKey:
		r.circuit = func() (frontend.Circuit, error) { return new(policy.KeyRegisterCircuit), nil }
		r.params = newParams[KeyRegisterParams]
	case common.RingDeposit:
		r.circuit = func() (frontend.Circuit, error) { return new(deposit.CustomRingDepositCircuit), nil }
		r.params = newParams[DepositParams]
	case common.RingAnonymousMerge:
		r.circuit = func() (frontend.Circuit, error) { return merge.NewAnonymousMergeCircuit(key.Inputs), nil }
		r.params = newParams[AnonymousMergeParams]
	default:
		panic(fmt.Sprintf("custom-ring: no circuit for ring family %d", key.Family))
	}
	return r
}

func anonymousShape(key common.RingKey) base.AnonymousAuditShape {
	return base.AnonymousAuditShape{InputClass: key.Inputs, Outputs: key.Outputs, FullOpenings: key.Family == common.RingAnonymousEntryAudit}
}

func sized[S any, C frontend.Circuit](constructor func(S) (C, error), shape S) func() (frontend.Circuit, error) {
	return func() (frontend.Circuit, error) { return constructor(shape) }
}

func newParams[P any]() any {
	return new(P)
}

func Ring(circuitType common.CircuitType) (RingCircuit, error) {
	for _, ring := range RingCircuits {
		if ring.Type == circuitType {
			return ring, nil
		}
	}
	return RingCircuit{}, fmt.Errorf("unknown custom-ring circuit type: %s", circuitType)
}

func Decode(circuitType common.CircuitType, payload []byte) (frontend.Circuit, error) {
	ring, err := Ring(circuitType)
	if err != nil {
		return nil, err
	}
	params := ring.params()
	if err := Unmarshal(payload, params); err != nil {
		return nil, err
	}
	return ring.Assign(params)
}

// Assign fails for a request that leaves a circuit value unset or sizes a slice off the key's shape.
func (r RingCircuit) Assign(params any) (frontend.Circuit, error) {
	assignment, err := r.circuit()
	if err != nil {
		return nil, err
	}
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
	circuit, err := r.circuit()
	if err != nil {
		return nil, err
	}
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
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
