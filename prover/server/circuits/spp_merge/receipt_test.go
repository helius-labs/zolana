package merge_test

import (
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

// receiptWitness turns a valid default-merge witness into the receipt-backed
// one: same values, no nullifier-tree witness. The public input is unchanged.
func receiptWitness(t *testing.T, from *merge.Circuit) *merge.Circuit {
	t.Helper()
	w := merge.NewReceiptMergeCircuit(from.NumInputs)
	w.Output = from.Output
	w.Asset = from.Asset
	w.OwnerPkHash = from.OwnerPkHash
	w.UserNullifierPk = from.UserNullifierPk
	w.UserNullifierSecret = from.UserNullifierSecret
	w.CommonPublicInputs = from.CommonPublicInputs
	w.UserSigningPkHash = from.UserSigningPkHash
	w.PublicInputHash = from.PublicInputHash
	for i, in := range from.Inputs {
		w.Inputs[i] = mergeshared.Input{
			Domain: in.Domain, Amount: in.Amount, Blinding: in.Blinding, RingDataHash: in.RingDataHash,
			StatePathElements: in.StatePathElements, StatePathIndex: in.StatePathIndex, TreeSlot: in.TreeSlot,
			NullifierLowValue: 0, NullifierNextValue: 0, NullifierLowPathIndex: 0,
		}
	}
	return w
}

func TestReceiptMergeProves(t *testing.T) {
	for _, eddsa := range []bool{false, true} {
		w := receiptWitness(t, buildWitness(t, eddsa))
		if err := test.IsSolved(merge.NewReceiptMergeCircuit(defaultFixtureInputs), w, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("eddsa=%t: %v", eddsa, err)
		}
	}
}

// The receipt variant keeps every constraint except non-inclusion, so a spent
// nullifier is no longer a circuit-level rejection: that is the receipt's job.
func TestReceiptMergeRejects(t *testing.T) {
	cases := map[string]func(*merge.Circuit){
		"state path":       func(w *merge.Circuit) { w.Inputs[1].StatePathElements[3] = big.NewInt(1) },
		"amount":           func(w *merge.Circuit) { w.Inputs[0].Amount = big.NewInt(1) },
		"published owner":  func(w *merge.Circuit) { w.UserSigningPkHash = big.NewInt(9) },
		"public input":     func(w *merge.Circuit) { w.PublicInputHash = big.NewInt(1) },
		"stray low value":  func(w *merge.Circuit) { w.Inputs[2].NullifierLowValue = big.NewInt(1) },
		"stray path index": func(w *merge.Circuit) { w.Inputs[2].NullifierLowPathIndex = big.NewInt(1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := receiptWitness(t, buildValidWitness(t))
			mutate(w)
			if err := test.IsSolved(merge.NewReceiptMergeCircuit(defaultFixtureInputs), w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("invalid receipt merge satisfied the circuit")
			}
		})
	}
}

func TestReceiptMergeRejectsNullifierPaths(t *testing.T) {
	w := receiptWitness(t, buildValidWitness(t))
	w.Inputs[0].NullifierLowPathElements = make([]frontend.Variable, 40)
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, w); err == nil {
		t.Fatal("receipt merge accepted a nullifier path")
	}
}

func TestReceiptMergeConstraints(t *testing.T) {
	if os.Getenv("MERGE_COUNTS") == "" {
		t.Skip("set MERGE_COUNTS to compile both variants")
	}
	for _, n := range mergeshared.SupportedInputCounts {
		for name, c := range map[string]frontend.Circuit{"merge": merge.NewMergeCircuit(n), "merge_receipt": merge.NewReceiptMergeCircuit(n)} {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("MERGE_COMPILE kind=%s inputs=%d constraints=%d", name, n, cs.GetNbConstraints())
		}
	}
}
