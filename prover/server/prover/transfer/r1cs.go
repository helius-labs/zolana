package transfer

import (
	txcircuit "zolana/prover/circuits/spp_transaction"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// R1CSTransfer compiles the P256-capable spp_transaction circuit for the given
// shape. WithCompressThreshold(300) matches the constraint system the committed
// verifying key was produced with (the P256 rail adds a BSB22 commitment the
// on-chain Groth16Verifier expects); do not drop it.
func R1CSTransfer(nInputs uint32, nOutputs uint32, confidential bool) (constraint.ConstraintSystem, error) {
	shape := txcircuit.Shape{NInputs: int(nInputs), NOutputs: int(nOutputs)}
	newCircuit := selectP256Constructor(confidential)
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

// selectP256Constructor picks the P256-rail circuit constructor. The two forms
// are confidential (non-zone) and zone (anonymous).
func selectP256Constructor(confidential bool) func(txcircuit.Shape) (*txcircuit.Circuit, error) {
	if confidential {
		return txcircuit.NewTransferP256ConfidentialCircuit
	}
	return txcircuit.NewTransferP256ZoneCircuit
}
