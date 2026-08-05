package aggregate

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// SetupAggregate runs trusted setup for one aggregate proving system, one
// inner verifying key per slot in slot order.
//
// The outer circuit compiles the inner verifying keys in, so the inner keys
// must already exist and an inner key rotation invalidates every aggregate key
// built from it.
func SetupAggregate(p Params, innerVks []groth16.VerifyingKey) (*common.AggregateProofSystem, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	fmt.Printf("Setting up aggregate %s\n", p.KeyName())
	ccs, err := R1CSAggregate(p, innerVks)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	fmt.Printf("Aggregate constraints: %d\n", ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	return &common.AggregateProofSystem{
		Slots:            p.Slots,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

// SetupAggregateUniform batches one transfer rail against its proving system,
// checking that the system matches every slot of p.
func SetupAggregateUniform(p Params, inner *common.TransferProofSystem) (*common.AggregateProofSystem, error) {
	if inner == nil {
		return nil, fmt.Errorf("aggregate setup needs the inner proving system")
	}
	slot, ok := common.UniformSlots(p.Slots)
	if !ok {
		return nil, fmt.Errorf("%s is not a uniform batch", p.KeyName())
	}
	if inner.CircuitType != slot.Inner {
		return nil, fmt.Errorf("inner system is %q, params name %q", inner.CircuitType, slot.Inner)
	}
	if inner.NInputs != slot.NInputs || inner.NOutputs != slot.NOutputs {
		return nil, fmt.Errorf(
			"inner system is %dx%d, params name %dx%d",
			inner.NInputs, inner.NOutputs, slot.NInputs, slot.NOutputs,
		)
	}
	vks := make([]groth16.VerifyingKey, len(p.Slots))
	for i := range vks {
		vks[i] = inner.VerifyingKey
	}
	return SetupAggregate(p, vks)
}
