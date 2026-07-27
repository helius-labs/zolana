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
	"zolana/prover/prover-test/spp/protocol"
)

// TestMergeCircuitCompiles is a smoke test: it confirms the 8-in / 1-out merge
// circuit compiles to R1CS.
func TestMergeCircuitCompiles(t *testing.T) {
	circuit := merge.NewMergeCircuit()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatalf("compile merge circuit: %v", err)
	}
	t.Logf("merge 8x1 R1CS constraints: %d", cs.GetNbConstraints())
}

func TestMergeCircuitRejectsMalformedLayout(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*merge.Circuit)
		want   string
	}{
		{
			name: "configured input count",
			mutate: func(c *merge.Circuit) {
				c.NumInputs--
			},
			want: "NumInputs must be",
		},
		{
			name: "input count",
			mutate: func(c *merge.Circuit) {
				c.Inputs = c.Inputs[:len(c.Inputs)-1]
			},
			want: "input count mismatch",
		},
		{
			name: "nullifier count",
			mutate: func(c *merge.Circuit) {
				c.Nullifiers = c.Nullifiers[:len(c.Nullifiers)-1]
			},
			want: "nullifier count mismatch",
		},
		{
			name: "utxo root count",
			mutate: func(c *merge.Circuit) {
				c.UtxoTreeRoots = c.UtxoTreeRoots[:len(c.UtxoTreeRoots)-1]
			},
			want: "utxo tree root count mismatch",
		},
		{
			name: "nullifier root count",
			mutate: func(c *merge.Circuit) {
				c.NullifierTreeRoots = c.NullifierTreeRoots[:len(c.NullifierTreeRoots)-1]
			},
			want: "nullifier tree root count mismatch",
		},
		{
			name: "state path height",
			mutate: func(c *merge.Circuit) {
				path := c.Inputs[0].StatePathElements
				c.Inputs[0].StatePathElements = path[:len(path)-1]
			},
			want: "state path height",
		},
		{
			name: "nullifier path height",
			mutate: func(c *merge.Circuit) {
				path := c.Inputs[0].NullifierLowPathElements
				c.Inputs[0].NullifierLowPathElements = path[:len(path)-1]
			},
			want: "nullifier path height",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			circuit := merge.NewMergeCircuit()
			tc.mutate(circuit)
			_, err := frontend.Compile(
				ecc.BN254.ScalarField(),
				r1cs.NewBuilder,
				circuit,
				frontend.WithCompressThreshold(300),
			)
			if err == nil {
				t.Fatal("expected malformed layout to fail compilation")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: got %q want substring %q", err, tc.want)
			}
		})
	}
}

// TestMergeCircuitProves checks the valid witness satisfies every constraint via
// the gnark test engine.
func TestMergeCircuitProves(t *testing.T) {
	assignment := buildValidWitness(t)
	if err := test.IsSolved(merge.NewMergeCircuit(), assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("merge witness not solved: %v", err)
	}
}

func TestMergeCircuitProvesEddsaOwner(t *testing.T) {
	assignment := buildWitness(t, true)
	if err := test.IsSolved(merge.NewMergeCircuit(), assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("eddsa merge witness not solved: %v", err)
	}
}

func TestMergeCircuitRejectsDummyInputsWhenPolicyDisabled(t *testing.T) {
	assignment := buildDefaultWitness(t, mergeFixtureOptions{
		allowDummyInputs: big.NewInt(0),
	})
	if err := test.IsSolved(merge.NewMergeCircuit(), assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected dummy-input policy failure, got solved")
	}
}

func TestMergeCircuitRejectsEddsaOwnerMismatch(t *testing.T) {
	a := buildWitness(t, true)
	a.OwnerPkHash = big.NewInt(0xBADBAD)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected eddsa ownership-uniformity failure, got solved")
	}
}

func TestMergeCircuitRejectsBadValueConservation(t *testing.T) {
	a := buildValidWitness(t)
	a.Inputs[0].Amount = big.NewInt(999)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected value-conservation failure, got solved")
	}
}

func TestMergeCircuitRejectsTamperedPublicInput(t *testing.T) {
	a := buildValidWitness(t)
	a.ExternalDataHash = big.NewInt(0xDEAD)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected public-input-hash failure, got solved")
	}
}

func TestMergeCircuitRejectsWrongAsset(t *testing.T) {
	a := buildValidWitness(t)
	a.Asset = big.NewInt(0xBADBAD)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected asset-uniformity failure, got solved")
	}
}

// Asset zero is reserved for content-less slots. Build an otherwise internally
// consistent asset-zero merge so only the real-output asset invariant rejects it.
func TestMergeCircuitRejectsZeroAsset(t *testing.T) {
	a := buildDefaultWitness(t, mergeFixtureOptions{asset: big.NewInt(0)})
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected zero-asset failure, got solved")
	}
}

func TestMergeCircuitRejectsWrongOwner(t *testing.T) {
	a := buildValidWitness(t)
	a.OwnerPkHash = big.NewInt(0xBADBAD)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected ownership-uniformity failure, got solved")
	}
}

func TestMergeCircuitRejectsInvalidDomain(t *testing.T) {
	a := buildValidWitness(t)
	a.Inputs[0].Domain = big.NewInt(protocol.AddressDomain)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected domain-partition failure, got solved")
	}
}

func TestMergeCircuitRejectsNonzeroDefaultZoneData(t *testing.T) {
	tests := []struct {
		name    string
		options mergeFixtureOptions
	}{
		{
			name: "real input",
			options: mergeFixtureOptions{
				inputZoneData: []*big.Int{big.NewInt(1), big.NewInt(0)},
			},
		},
		{
			name: "output",
			options: mergeFixtureOptions{
				outputZoneData: big.NewInt(1),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := buildDefaultWitness(t, tc.options)
			if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("expected default-zone data assertion to fail, got solved")
			}
		})
	}
}

func TestMergeCircuitRejectsNonzeroDummyZoneData(t *testing.T) {
	a := buildValidWitness(t)
	a.Inputs[2].ZoneDataHash = big.NewInt(1)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected canonical-dummy failure, got solved")
	}
}

func TestMergeCircuitRejectsBadDummyNonInclusionProof(t *testing.T) {
	a := buildValidWitness(t)
	a.Inputs[2].NullifierLowPathElements[0] = big.NewInt(1)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected dummy nullifier non-inclusion failure, got solved")
	}
}

func TestMergeCircuitRejectsWrongPublishedOwnerHash(t *testing.T) {
	a := buildDefaultWitness(t, mergeFixtureOptions{
		userSigningPkHash: big.NewInt(0xBADBAD),
	})
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected published owner-hash binding to fail, got solved")
	}
}

// Slot zero must be real: the output blinding derives from its blinding, so a
// dummy slot zero would make the output blinding publicly computable from the
// merge view tag.
func TestMergeCircuitRejectsDummySlotZero(t *testing.T) {
	a := buildValidWitness(t)
	a.Inputs[0].Domain = big.NewInt(protocol.DummyDomain)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected slot-zero-real failure, got solved")
	}
}

// A wrong first nullifier cannot match the in-circuit derivation.
func TestMergeCircuitRejectsWrongFirstNullifier(t *testing.T) {
	a := buildValidWitness(t)
	a.Nullifiers[0] = big.NewInt(0xBAD)
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected first-nullifier binding to fail, got solved")
	}
}

// The same real input in two slots passes inclusion, non-inclusion, and value
// conservation (the fixture keeps every other constraint consistent); only
// nullifier distinctness rejects it. Without it the input's value would be
// double-counted in the output.
func TestMergeCircuitRejectsDuplicateRealInput(t *testing.T) {
	a := buildDefaultWitness(t, mergeFixtureOptions{duplicateFirstInput: true})
	if err := test.IsSolved(merge.NewMergeCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected nullifier-distinctness failure, got solved")
	}
}
