package merge_test

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	merge "github.com/helius-labs/zolana/prover/server/circuits/spp_merge"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
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

// The ring rail binds no output ciphertext: its public-input-hash preimage is
// the common prefix followed by exactly the output ring-data hash and the ring
// program id, with no salt or ciphertext tail, and the circuit carries no salt
// witness, so the proof is the same whatever salt the instruction carries.
func TestMergeRingPublicInputsHaveNoCiphertextTail(t *testing.T) {
	f := buildMergeFixture(t, mergeFixtureOptions{
		rail:           ringFixtureRail,
		ringProgramID:  big.NewInt(0xC0FFEE),
		inputRingData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)},
		outputRingData: big.NewInt(0xD2),
	})
	const commonPrefixLen = 7
	if got, want := len(f.publicInputPreimage), commonPrefixLen+2; got != want {
		t.Fatalf("ring preimage length: got %d want %d", got, want)
	}
	tail := f.publicInputPreimage[commonPrefixLen:]
	if tail[0].Cmp(f.outputRingDataHash) != 0 || tail[1].Cmp(f.ringProgramID) != 0 {
		t.Fatalf("ring preimage tail: got %v", tail)
	}
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), f.ringCircuit(), ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("ring merge witness not solved: %v", err)
	}

	// Appending a salt and ciphertext to the preimage, as the default rail
	// does, must not solve: the ring hash has no such tail.
	ciphertext, err := protocol.MergeOutputCiphertext(
		f.userNullifierSecret, f.public.Nullifiers[0].(*big.Int), fixtureCiphertextSalt,
		big.NewInt(5+7), fixtureMint,
	)
	if err != nil {
		t.Fatal(err)
	}
	f.publicInputPreimage = append(append(f.publicInputPreimage, fixtureCiphertextSalt), ciphertext...)
	f.publicInputHash = hashChain4(t, f.publicInputPreimage)
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), f.ringCircuit(), ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ring merge solved with a ciphertext tail in its public-input hash")
	}
}
