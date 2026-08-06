package aggregate

import (
	"fmt"

	aggregatecircuit "zolana/prover/circuits/spp_aggregate"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// R1CSAggregate compiles the outer circuit for p against one inner verifying
// key per slot, in slot order.
//
// The verifying keys are fixed at compile time, so a change to any inner key
// changes the outer key. Regenerate them together.
func R1CSAggregate(p Params, innerVks []groth16.VerifyingKey) (constraint.ConstraintSystem, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(innerVks) != len(p.Slots) {
		return nil, fmt.Errorf("%d inner keys against %d slots", len(innerVks), len(p.Slots))
	}
	fixed := make([]aggregatecircuit.InnerVerifyingKey, len(innerVks))
	for i, vk := range innerVks {
		var err error
		if fixed[i], err = stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk); err != nil {
			return nil, fmt.Errorf("fix inner verifying key %d: %w", i, err)
		}
	}
	circuit, err := aggregatecircuit.NewCircuit(fixed)
	if err != nil {
		return nil, fmt.Errorf("new aggregate circuit: %w", err)
	}
	// WithCompressThreshold(300) matches the inner rails, keeping one
	// compression policy across every committed verifying key in the tree.
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
}
