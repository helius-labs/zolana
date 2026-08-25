package custom_ring

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/circuits/custom_ring/audit"
	"zolana/prover/circuits/custom_ring/policy"
)

func R1CSCustomRingAudit() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&audit.Circuit{},
		frontend.WithCompressThreshold(300),
	)
}

func R1CSCustomRingPolicy() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&policy.Circuit{},
		frontend.WithCompressThreshold(300),
	)
}
