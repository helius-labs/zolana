package custom_ring

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

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
	ring[BaseParams, base.CustomRingCompactConfidentialCircuit](common.CustomRingCompactConfidentialCircuitType),
	ring[BaseParams, base.CustomRingWideBaseCircuit](common.CustomRingWideAnonymousCircuitType),
	ring[DelegatePolicyParams, policy.CustomRingDelegatePolicyCircuit](common.CustomRingDelegatePolicyCircuitType),
	ring[KeyRegisterParams, policy.KeyRegisterCircuit](common.CustomRingKeyRegisterCircuitType),
	ring[DepositParams, deposit.CustomRingDepositCircuit](common.CustomRingDepositCircuitType),
	ring[UpdateMembersParams, registry.UpdateMembersCircuit](common.CustomRingUpdateMembersCircuitType),
	twoByThreeRing(common.CustomRingPolicyTwoByThreeCircuitType, false, false),
	twoByThreeRing(common.CustomRingAnonymousPolicyTwoByThreeCircuitType, true, false),
	twoByThreeRing(common.CustomRingDelegatePolicyTwoByThreeCircuitType, false, true),
}

func init() {
	for _, width := range common.MergeAnonymousWidths {
		RingCircuits = append(RingCircuits, RingCircuit{
			Type:    common.CustomRingMergeAnonymousCircuitType(width),
			Circuit: func() frontend.Circuit { return merge.New(width) },
			params:  func() any { return new(MergeAnonymousParams) },
		})
	}
	for _, shape := range common.RingPolicyShapes {
		RingCircuits = append(RingCircuits, RingCircuit{Type: shape.CircuitType(), params: policyParamsFactory(shape.CircuitType()), Circuit: func() frontend.Circuit {
			return policy.NewShapeCircuit(shape.NInputs, shape.NOutputs, shape.Anonymous, shape.Delegate, shape.Subtree)
		}})
	}
}

func twoByThreeRing(kind common.CircuitType, anonymous, delegate bool) RingCircuit {
	return RingCircuit{Type: kind, params: policyParamsFactory(kind), Circuit: func() frontend.Circuit {
		return &policy.PublicTableTwoByThreeCircuit{Circuit: policy.TwoByThreeCircuit{Anonymous: anonymous, Delegate: delegate}}
	}}
}

func policyParamsFactory(circuitType common.CircuitType) func() any {
	return func() any {
		value, _ := NewPolicyParams(circuitType)
		return value
	}
}

// NewPolicyParams selects the request wrapper and the contained policy once for
// both direct proof requests and indexed requests.
func NewPolicyParams(circuitType common.CircuitType) (any, *PolicyParams) {
	shape, shaped := common.ParseRingPolicyShape(circuitType)
	delegate := circuitType == common.CustomRingDelegatePolicyCircuitType ||
		circuitType == common.CustomRingDelegatePolicyTwoByThreeCircuitType || shaped && shape.Delegate
	if delegate {
		wrapper := new(DelegatePolicyParams)
		return wrapper, &wrapper.Policy
	}
	p := new(PolicyParams)
	return p, p
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
	if circuitType == common.CustomRingConfidentialCircuitType || circuitType == common.CustomRingCompactConfidentialCircuitType {
		baseParams := params.(*BaseParams)
		if baseParams.Anonymous || baseParams.NOut != 2 {
			return nil, fmt.Errorf("confidential audit circuit requires ordinary mode and two outputs")
		}
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
	if shaped, ok := assignment.(*policy.ShapeCircuit); ok {
		return assignShapedPolicy(shaped, params)
	}
	if fast, ok := assignment.(*policy.PublicTableTwoByThreeCircuit); ok {
		if delegated, ok := params.(*DelegatePolicyParams); ok {
			params = &delegated.Policy
		}
		if err := assign(&fast.Circuit.Policy, params); err != nil {
			return nil, err
		}
		return policy.AssignPublicTable(&fast.Circuit.Policy, fast.Circuit.Anonymous, fast.Circuit.Delegate)
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

func assignShapedPolicy(c *policy.ShapeCircuit, params any) (frontend.Circuit, error) {
	if delegated, ok := params.(*DelegatePolicyParams); ok {
		params = &delegated.Policy
	}
	p, ok := params.(*PolicyParams)
	if !ok {
		return nil, fmt.Errorf("invalid shaped policy params %T", params)
	}
	dst := reflect.ValueOf(&c.Policy).Elem()
	shapeType := reflect.TypeOf(c.ShapeWires)
	for i := 0; i < shapeType.NumField(); i++ {
		shapeField := shapeType.Field(i)
		policyField, ok := dst.Type().FieldByName(shapeField.Name)
		if !ok || policyField.Tag.Get("shape") != "dynamic" || shapeField.Type.Kind() != reflect.Slice || policyField.Type.Kind() != reflect.Array || policyField.Type.Elem() != shapeField.Type.Elem() {
			return nil, fmt.Errorf("shape wire %s has no matching policy field", shapeField.Name)
		}
	}
	errs := fill(dst, reflect.Value{}, "")
	src := reflect.ValueOf(p).Elem()
	for i := 0; i < dst.NumField(); i++ {
		field := dst.Type().Field(i)
		if field.Tag.Get("gnark") == "-" {
			continue
		}
		if field.Tag.Get("shape") == "dynamic" {
			shapeField, ok := shapeType.FieldByName(field.Name)
			if !ok || shapeField.Type.Kind() != reflect.Slice || field.Type.Kind() != reflect.Array || shapeField.Type.Elem() != field.Type.Elem() {
				return nil, fmt.Errorf("shape wire %s has no matching dynamic field", field.Name)
			}
			continue
		}
		if field.Tag.Get("shape") != "" {
			return nil, fmt.Errorf("shape wire %s has unknown assignment tag", field.Name)
		}
		value := src.FieldByName(field.Name)
		if field.Anonymous {
			value = src
		}
		errs = append(errs, fill(dst.Field(i), value, field.Name)...)
	}
	errs = append(errs, fill(reflect.ValueOf(&c.ShapeWires).Elem(), src, "")...)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	c.Policy.Dynamic = &c.ShapeWires
	if len(c.Registry) != 0 {
		c.Policy.RegistrySubtreeDepth = registry.SparseSubtreeDepth
	}
	table, err := policy.AssignPublicTable(&c.Policy, c.Anonymous, c.Delegate)
	if err != nil {
		return nil, err
	}
	c.Table, c.TreeHash = table.Table, table.TreeHash
	if len(c.Registry) != 0 {
		copy(c.Registry, table.Registry[:])
	}
	return c, nil
}
