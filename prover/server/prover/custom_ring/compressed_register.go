package custom_ring

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover/common"
)

func R1CSCompressedRegister() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		&policy.CompressedRegisterCircuit{},
		frontend.WithCompressThreshold(300),
	)
}

func SetupCompressedRegister() (*common.RingProofSystem, error) {
	ccs, err := R1CSCompressedRegister()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return compressedRegisterProofSystem(pk, vk, ccs), nil
}

// ConvertCompressedRegister combines existing keys with the compiled head registration circuit.
type ConvertCompressedRegister struct {
	ProvingKeyPath   string
	VerifyingKeyPath string
}

func (c ConvertCompressedRegister) Run() (*common.RingProofSystem, error) {
	ccs, err := R1CSCompressedRegister()
	if err != nil {
		return nil, err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readKey(c.ProvingKeyPath, pk); err != nil {
		return nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readKey(c.VerifyingKeyPath, vk); err != nil {
		return nil, err
	}
	return compressedRegisterProofSystem(pk, vk, ccs), nil
}

func compressedRegisterProofSystem(pk groth16.ProvingKey, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) *common.RingProofSystem {
	return &common.RingProofSystem{
		CircuitType:      common.CompressedRegisterCircuitType,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
}
