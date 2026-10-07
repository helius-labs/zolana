package merge

import (
	mergecircuit "zolana/prover/circuits/spp_merge"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func R1CSMerge(nInputs int) (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		mergecircuit.NewMergeCircuit(nInputs),
		frontend.WithCompressThreshold(300),
	)
}

func R1CSMergeRing(nInputs int) (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		mergecircuit.NewMergeRingCircuit(nInputs),
		frontend.WithCompressThreshold(300),
	)
}
