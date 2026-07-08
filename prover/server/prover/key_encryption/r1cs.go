package keyencryption

import (
	kecircuit "zolana/prover/circuits/squads/key_encryption"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// R1CSKeyEncryption compiles the squads key encryption circuit for numKeys
// recovery-plus-auditor recipients. WithCompressThreshold(300) matches the
// BSB22 commitment from the emulated-P256 scalar mul.
func R1CSKeyEncryption(numKeys uint32) (constraint.ConstraintSystem, error) {
	circuit := kecircuit.NewKeyEncryptionCircuit(int(numKeys))
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
}
