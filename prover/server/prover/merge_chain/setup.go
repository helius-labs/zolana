package merge_chain

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// SetupMergeChain runs trusted setup for one merge-chain proving system.
//
// The outer circuit compiles in the merge verifying key, so the merge key must
// already exist and a merge key rotation invalidates every chain key built from
// it.
func SetupMergeChain(p Params, inner *common.TransferProofSystem) (*common.MergeChainProofSystem, error) {
	shape, err := p.Shape()
	if err != nil {
		return nil, err
	}
	if inner == nil {
		return nil, fmt.Errorf("merge chain setup needs the merge proving system")
	}
	if inner.CircuitType != common.MergeCircuitType {
		return nil, fmt.Errorf("inner system is %q, want %q", inner.CircuitType, common.MergeCircuitType)
	}

	fmt.Printf("Setting up merge chain: levels %v, %d legs, %d tree inputs\n",
		p.Levels, shape.Legs(), shape.TreeInputs())
	ccs, err := R1CSMergeChain(p, inner.ConstraintSystem, inner.VerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	fmt.Printf("Merge chain constraints: %d\n", ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	return &common.MergeChainProofSystem{
		Levels:           p.Levels32(),
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
