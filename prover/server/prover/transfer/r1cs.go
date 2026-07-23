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
	circuit, err := newP256Circuit(confidential, shape)
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

// newP256Circuit builds the P256-rail circuit. The two forms are default zone
// (confidential) and custom zone (anonymous).
func newP256Circuit(confidential bool, shape txcircuit.Shape) (frontend.Circuit, error) {
	if confidential {
		return txcircuit.NewDefaultZoneP256Circuit(shape)
	}
	return txcircuit.NewCustomZoneP256Circuit(shape)
}

// wrapP256Assignment wraps a filled witness core in the variant circuit type so
// gnark sees the same schema the constraint system was compiled with.
func wrapP256Assignment(confidential bool, core txcircuit.Circuit) frontend.Circuit {
	if confidential {
		return &txcircuit.DefaultZoneP256Circuit{Circuit: core}
	}
	return &txcircuit.CustomZoneP256Circuit{Circuit: core}
}
