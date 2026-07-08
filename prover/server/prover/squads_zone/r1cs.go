package squadszone

import (
	"fmt"

	zonecircuit "zolana/prover/circuits/squads/zone"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// newZoneCircuit allocates the squads zone circuit for the given shape:
// nOutputs == 2 is a transfer, nOutputs == 1 a withdrawal.
func newZoneCircuit(nInputs uint32, nOutputs uint32) (*zonecircuit.Circuit, error) {
	switch nOutputs {
	case 2:
		return zonecircuit.NewTransferCircuit(int(nInputs)), nil
	case 1:
		return zonecircuit.NewWithdrawalCircuit(int(nInputs)), nil
	default:
		return nil, fmt.Errorf("squads zone: unsupported nOutputs %d (want 1 or 2)", nOutputs)
	}
}

// R1CSZone compiles the squads zone circuit for the given shape.
// WithCompressThreshold(300) matches the transfer shape's BSB22 commitment
// (from the emulated-P256 scalar mul), same as the transfer-p256 rail.
func R1CSZone(nInputs uint32, nOutputs uint32) (constraint.ConstraintSystem, error) {
	circuit, err := newZoneCircuit(nInputs, nOutputs)
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
