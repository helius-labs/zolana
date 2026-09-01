package custom_ring

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	customring "zolana/prover/circuits/custom_ring"
)

// The audit-only rail proves just the audit block, the same eight-element
// statement the folded circuit carries as its prefix.

func R1CSAudit() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&customring.Circuit{},
		frontend.WithCompressThreshold(300),
	)
}

func SetupAudit() (groth16.ProvingKey, groth16.VerifyingKey, error) {
	ccs, err := R1CSAudit()
	if err != nil {
		return nil, nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}
