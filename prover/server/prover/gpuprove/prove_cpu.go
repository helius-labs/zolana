//go:build !cuda

package gpuprove

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

const gpuBuilt = false

func gpuAvailable() bool { return false }

// proveGPU is unreachable, UseGPU never selects the GPU in a CPU-only build.
// It must not call the gnark icicle stub, which panics.
func proveGPU(constraint.ConstraintSystem, groth16.ProvingKey, witness.Witness) (groth16.Proof, error) {
	return nil, errors.New("gpu prove requested in a binary built without the cuda tag")
}

func proveCPU(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	return groth16.Prove(ccs, pk, w)
}

// NewProvingKey allocates the key type the selected backend can consume.
func NewProvingKey() groth16.ProvingKey {
	return groth16.NewProvingKey(ecc.BN254)
}
