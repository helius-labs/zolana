package merge_test

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
)

func TestMergeRingCircuitValidatesPublicSignalLayout(t *testing.T) {
	circuit := merge.NewMergeRingCircuit(defaultFixtureInputs)
	circuit.Nullifiers = circuit.Nullifiers[:len(circuit.Nullifiers)-1]

	_, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
	if err == nil {
		t.Fatal("expected malformed ring layout to fail compilation")
	}
	if want := "nullifier count mismatch"; !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: got %q want substring %q", err, want)
	}
}

func TestMergeRingCircuitProves(t *testing.T) {
	assignment := buildRingWitness(t, big.NewInt(0x5A0E))
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("ring merge witness not solved: %v", err)
	}
}

func TestMergeRingCircuitRejectsWrongRingProgram(t *testing.T) {
	a := buildRingWitness(t, big.NewInt(0x5A0E))
	a.RingProgramID = big.NewInt(0)
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected ring-binding failure for wrong ring program, got solved")
	}
}

// A zero ring program would collapse the policy-ring rail into default-ring
// UTXO semantics. Build a self-consistent zero-ring witness to isolate the
// explicit nonzero-ring invariant.
func TestMergeRingCircuitRejectsZeroRingProgram(t *testing.T) {
	a := buildRingWitness(t, big.NewInt(0))
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected zero-ring-program failure, got solved")
	}
}

// The carried output ring-data hash must equal Output.Utxo.RingDataHash; a
// mismatch means the instruction/event does not describe the proven output.
func TestMergeRingCircuitRejectsWrongOutputRingDataHash(t *testing.T) {
	a := buildRingWitness(t, big.NewInt(0x5A0E))
	a.OutputRingDataHash = big.NewInt(0xBAD)
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected output ring-data-hash binding to fail, got solved")
	}
}
