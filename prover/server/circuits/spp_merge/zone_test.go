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

func TestMergeZoneCircuitValidatesPublicSignalLayout(t *testing.T) {
	circuit := merge.NewMergeZoneCircuit()
	circuit.Nullifiers = circuit.Nullifiers[:len(circuit.Nullifiers)-1]

	_, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
	if err == nil {
		t.Fatal("expected malformed zone layout to fail compilation")
	}
	if want := "nullifier count mismatch"; !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: got %q want substring %q", err, want)
	}
}

func TestMergeZoneCircuitProves(t *testing.T) {
	assignment := buildZoneWitness(t, big.NewInt(0x5A0E))
	if err := test.IsSolved(merge.NewMergeZoneCircuit(), assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("zone merge witness not solved: %v", err)
	}
}

func TestMergeZoneCircuitRejectsWrongZoneProgram(t *testing.T) {
	a := buildZoneWitness(t, big.NewInt(0x5A0E))
	a.ZoneProgramID = big.NewInt(0)
	if err := test.IsSolved(merge.NewMergeZoneCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected zone-binding failure for wrong zone program, got solved")
	}
}
