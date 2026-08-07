package squads_zone_fold

import (
	"fmt"

	foldcircuit "zolana/prover/circuits/squads/zone_fold"
	squadszone "zolana/prover/prover/squads_zone"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// InnerSystem compiles the zone circuit so the outer circuit can be built
// against its constraint system. Setup also needs the inner verifying key,
// which only exists in the inner proving system, so the caller supplies that.
func InnerSystem(p Params) (constraint.ConstraintSystem, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return squadszone.R1CSZone(p.NInputs, p.NOutputs)
}

// R1CSFold compiles the outer circuit for p against the inner constraint system
// and verifying key.
//
// The verifying key is fixed at compile time, so a change to the inner key
// changes the outer key. Regenerate both together.
func R1CSFold(p Params, innerCcs constraint.ConstraintSystem, innerVk groth16.VerifyingKey) (constraint.ConstraintSystem, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	if err != nil {
		return nil, fmt.Errorf("fix inner verifying key: %w", err)
	}
	circuit, err := foldcircuit.NewCircuit(int(p.Legs), int(p.NOutputs), fixed, innerCcs)
	if err != nil {
		return nil, fmt.Errorf("new fold circuit: %w", err)
	}
	// WithCompressThreshold(300) matches every other committed verifying key,
	// keeping one compression policy across the tree.
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
}
