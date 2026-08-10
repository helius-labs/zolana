package squadsring

import (
	"fmt"

	ringcircuit "zolana/prover/circuits/squads/ring"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func newRingCircuit(nInputs uint32, nOutputs uint32) (*ringcircuit.Circuit, error) {
	switch nOutputs {
	case 2:
		return ringcircuit.NewTransferCircuit(int(nInputs)), nil
	case 1:
		return ringcircuit.NewWithdrawalCircuit(int(nInputs)), nil
	default:
		return nil, fmt.Errorf("squads ring: unsupported nOutputs %d (want 1 or 2)", nOutputs)
	}
}

// R1CSRing compiles the squads ring circuit for the given shape.
// WithCompressThreshold(300) matches the transfer shape's BSB22 commitment
// (from the emulated-P256 scalar mul), same as the transfer-p256 rail.
func R1CSRing(nInputs uint32, nOutputs uint32) (constraint.ConstraintSystem, error) {
	circuit, err := newRingCircuit(nInputs, nOutputs)
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
