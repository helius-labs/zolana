package transfereddsaonly

import (
	txcircuit "zolana/prover/circuits/spp_transaction"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// R1CSTransfer compiles the Solana-only spp_transaction circuit for the given
// shape (no P256 gadget). WithCompressThreshold(300) matches the constraint
// system the committed verifying key was produced with; do not drop it.
func R1CSTransfer(nInputs uint32, nOutputs uint32, confidential bool) (constraint.ConstraintSystem, error) {
	shape := txcircuit.Shape{NInputs: int(nInputs), NOutputs: int(nOutputs)}
	newCircuit := txcircuit.NewTransferCircuit
	if confidential {
		newCircuit = txcircuit.NewTransferConfidentialCircuit
	}
	circuit, err := newCircuit(shape)
	if err != nil {
		return nil, err
	}
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
}
