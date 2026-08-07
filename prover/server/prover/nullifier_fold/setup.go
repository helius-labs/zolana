package nullifier_fold

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark/backend/groth16"
)

// SetupFold runs trusted setup for one fold proving system.
//
// The outer circuit compiles in the inner verifying key, so the inner key must
// already exist and an inner key rotation invalidates every fold key built from
// it.
func SetupFold(p Params, inner *common.BatchProofSystem) (*common.NullifierFoldProofSystem, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if inner == nil {
		return nil, fmt.Errorf("fold setup needs the inner proving system")
	}
	if inner.CircuitType != common.BatchAddressAppendCircuitType {
		return nil, fmt.Errorf("inner system is %q, want %q", inner.CircuitType, common.BatchAddressAppendCircuitType)
	}
	if inner.TreeHeight != p.TreeHeight || inner.BatchSize != p.BatchSize {
		return nil, fmt.Errorf(
			"inner system is height %d batch %d, params name height %d batch %d",
			inner.TreeHeight, inner.BatchSize, p.TreeHeight, p.BatchSize,
		)
	}

	fmt.Printf("Setting up nullifier fold: height %d, batch %d, run %d\n", p.TreeHeight, p.BatchSize, p.Run)
	ccs, err := R1CSFold(p, inner.ConstraintSystem, inner.VerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	fmt.Printf("Fold constraints: %d\n", ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	return &common.NullifierFoldProofSystem{
		TreeHeight:       p.TreeHeight,
		BatchSize:        p.BatchSize,
		Run:              p.Run,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
