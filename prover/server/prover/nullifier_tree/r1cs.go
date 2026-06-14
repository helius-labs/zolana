package nullifiertree

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func R1CSBatchAddressAppend(height uint32, batchSize uint32) (constraint.ConstraintSystem, error) {
	circuit := InitBatchAddressTreeAppendCircuit(height, batchSize)
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
}
