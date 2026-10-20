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

func TestMergeRingCircuitSolves(t *testing.T) {
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

// A merge must use the key registration of the exact owner and nullifier key
// that authenticate its spent notes. Rehash the public statement when changing
// the root so the membership relation, not a stale public hash, rejects it.
func TestMergeRingBindsRecoveryRegistration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *mergeWitnessFixture)
	}{
		{"wrong root", func(t *testing.T, f *mergeWitnessFixture) {
			f.memberRegistryRoot = new(big.Int).Add(f.memberRegistryRoot, big.NewInt(1))
			refreshRingPublicInputHash(t, f)
		}},
		{"wrong escrow key", func(_ *testing.T, f *mergeWitnessFixture) {
			f.memberRecord.EscrowKey = new(big.Int).Add(f.memberRecord.EscrowKey.(*big.Int), big.NewInt(1))
		}},
		{"wrong ciphertext hash", func(_ *testing.T, f *mergeWitnessFixture) {
			f.registeredCtHash = new(big.Int).Add(f.registeredCtHash, big.NewInt(1))
		}},
		{"zero ciphertext hash", func(_ *testing.T, f *mergeWitnessFixture) {
			f.registeredCtHash = big.NewInt(0)
		}},
		{"wrong record index", func(_ *testing.T, f *mergeWitnessFixture) {
			f.memberRecord.Index = 2
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := buildMergeFixture(t, mergeFixtureOptions{
				rail: ringFixtureRail, ringProgramID: big.NewInt(0x5A0E),
				inputRingData: []*big.Int{big.NewInt(0xD0), big.NewInt(0xD0)}, outputRingData: big.NewInt(0xD0),
			})
			tc.mutate(t, f)
			assignment := f.ringCircuit()
			if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("merge accepted a mismatched recovery registration")
			}
		})
	}
}

// Build each opening and transcript from scratch so only state preservation,
// rather than a stale commitment or public hash, can reject the mutation.
func TestMergeRingPreservesEveryRealInputRingData(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inputs [2]int64
		output int64
		valid  bool
	}{
		{"zero_state", [2]int64{0, 0}, 0, true},
		{"common_state_with_dummy_padding", [2]int64{17, 17}, 17, true},
		{"erase_state", [2]int64{17, 17}, 0, false},
		{"replace_state", [2]int64{17, 17}, 19, false},
		{"first_input_differs", [2]int64{19, 17}, 17, false},
		{"second_input_differs", [2]int64{17, 19}, 17, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := buildMergeFixture(t, mergeFixtureOptions{
				inputCount: 8, rail: ringFixtureRail, ringProgramID: big.NewInt(0x5A),
				inputRingData:  []*big.Int{big.NewInt(tc.inputs[0]), big.NewInt(tc.inputs[1])},
				outputRingData: big.NewInt(tc.output),
			})
			err := test.IsSolved(merge.NewMergeRingCircuit(8), f.ringCircuit(), ecc.BN254.ScalarField())
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, got %v", tc.valid, err)
			}
		})
	}
}

func anonymousRingFixture(t *testing.T) *mergeWitnessFixture {
	t.Helper()
	return buildMergeFixture(t, mergeFixtureOptions{
		rail: ringFixtureRail, ringProgramID: big.NewInt(0x5A0E), anonymous: true,
		inputRingData: []*big.Int{big.NewInt(0xD0), big.NewInt(0xD0)}, outputRingData: big.NewInt(0xD0),
	})
}

// An anonymous member has no escrow key, the flag alone waives the escrow relation.
func TestMergeRingAnonymousSkipsTheEscrowKey(t *testing.T) {
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), anonymousRingFixture(t).ringCircuit(), ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("anonymous ring merge not solved: %v", err)
	}
}

// The flag is a public value, flipping it on either side of the statement fails.
func TestMergeRingBindsTheAnonymousFlag(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *mergeWitnessFixture)
	}{
		{"anonymous witness under a registered statement", func(t *testing.T, f *mergeWitnessFixture) {
			f.anonymous = big.NewInt(0)
			refreshRingPublicInputHash(t, f)
			f.anonymous = big.NewInt(1)
		}},
		{"unregistered member claims a registered merge", func(t *testing.T, f *mergeWitnessFixture) {
			f.anonymous = big.NewInt(0)
			refreshRingPublicInputHash(t, f)
		}},
		{"non-boolean flag", func(t *testing.T, f *mergeWitnessFixture) {
			f.anonymous = big.NewInt(2)
			refreshRingPublicInputHash(t, f)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := anonymousRingFixture(t)
			tc.mutate(t, f)
			if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), f.ringCircuit(), ecc.BN254.ScalarField()); err == nil {
				t.Fatal("merge accepted a tampered anonymous flag")
			}
		})
	}
	registered := buildRingWitness(t, big.NewInt(0x5A0E))
	registered.Anonymous = 1
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), registered, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("a registered merge solved with the anonymous flag outside its statement")
	}
}
