package custom_ring

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/circuits/custom_ring/auditor_key_encryption"
)

func R1CSAuditorKeyEncryption() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&auditor_key_encryption.Circuit{},
		frontend.WithCompressThreshold(300),
	)
}
