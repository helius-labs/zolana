package squads_key_encryption_fold

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
func SetupFold(p Params, inner *common.SquadsKeyEncryptionProofSystem) (*common.SquadsKeyEncryptionFoldProofSystem, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if inner == nil {
		return nil, fmt.Errorf("fold setup needs the inner proving system")
	}
	if inner.NumKeys != p.KeysPerLeg {
		return nil, fmt.Errorf("inner system proves %d keys, params name %d", inner.NumKeys, p.KeysPerLeg)
	}

	fmt.Printf("Setting up squads key encryption fold: %d legs of %d keys\n", p.Legs, p.KeysPerLeg)
	ccs, err := R1CSFold(p, inner.ConstraintSystem, inner.VerifyingKey)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	fmt.Printf("Fold constraints: %d\n", ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}
	return &common.SquadsKeyEncryptionFoldProofSystem{
		KeysPerLeg:       p.KeysPerLeg,
		Legs:             p.Legs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}
