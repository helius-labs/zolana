package merge

import (
	mergecircuit "zolana/prover/circuits/spp_merge"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// R1CSMerge compiles the 8-in/1-out merge circuit. WithCompressThreshold(300)
// matches the constraint system the committed verifying key is produced with
// (the emulated P256 gadget adds a BSB22 commitment); keep it in sync with the
// transfer rail and the verifying-key regeneration.
func R1CSMerge() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		mergecircuit.NewMergeCircuit(),
		frontend.WithCompressThreshold(300),
	)
}

// R1CSMergeZone compiles the policy-zone merge circuit (merge_zone). It mirrors
// R1CSMerge with the zone binding added, so the same compression threshold and
// BSB22 commitment apply.
func R1CSMergeZone() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		mergecircuit.NewMergeZoneCircuit(),
		frontend.WithCompressThreshold(300),
	)
}
