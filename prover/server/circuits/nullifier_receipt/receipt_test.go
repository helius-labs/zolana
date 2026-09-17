package receipt_test

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	receipt "zolana/prover/circuits/nullifier_receipt"
	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"
)

// fixture builds a receipt for `active` fresh nullifiers in an n-slot shape,
// against a nullifier tree holding 64 historical entries.
func fixture(t *testing.T, n, active int) *receipt.Circuit {
	t.Helper()
	w := receipt.New(n)
	nfs, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 64 {
		if err := nfs.Insert(hash(t, 991, i)); err != nil {
			t.Fatal(err)
		}
	}
	w.TreeID, w.Root, w.Count = 7, nfs.Root(), active
	for i := range n {
		w.Nullifiers[i] = 0
		w.Witnesses[i] = receipt.NonInclusion{Low: 0, Next: 0, Index: 0, Path: zeros(40)}
		if i >= active {
			continue
		}
		nullifier := hash(t, 7, i)
		witness, err := nfs.NonInclusionWitness(nullifier)
		if err != nil {
			t.Fatal(err)
		}
		w.Nullifiers[i] = nullifier
		w.Witnesses[i] = receipt.NonInclusion{
			Low: witness.LowValue, Next: witness.NextValue, Index: witness.LowIndex, Path: variables(witness.PathElements),
		}
	}
	bind(t, w)
	return w
}

// bind recomputes the public input natively, the way the program does.
func bind(t *testing.T, w *receipt.Circuit) {
	t.Helper()
	w.PublicInputHash = chain(t, []frontend.Variable{receipt.Domain, w.TreeID, w.Root, w.Count, chain(t, w.Nullifiers)})
}

func TestReceiptAcceptsFullAndPadded(t *testing.T) {
	for _, active := range []int{1, 3, 4} {
		if err := test.IsSolved(receipt.New(4), fixture(t, 4, active), ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("active=%d: %v", active, err)
		}
	}
}

func TestReceiptRejects(t *testing.T) {
	cases := map[string]func(*receipt.Circuit){
		"spent nullifier": func(w *receipt.Circuit) { w.Witnesses[1].Low = w.Nullifiers[1] },
		"wrong root":      func(w *receipt.Circuit) { w.Root = 1 },
		"wrong path":      func(w *receipt.Circuit) { w.Witnesses[2].Path[13] = 1 },
		"wrong index":     func(w *receipt.Circuit) { w.Witnesses[2].Index = 5 },
		"substitution":    func(w *receipt.Circuit) { w.Nullifiers[0] = 1 },
		"wrong count":     func(w *receipt.Circuit) { w.Count = 3 },
		"next below": func(w *receipt.Circuit) {
			w.Witnesses[3].Next = new(big.Int).Sub(integers(t, []frontend.Variable{w.Nullifiers[3]})[0], big.NewInt(1))
		},
		"padding gap": func(w *receipt.Circuit) {
			w.Nullifiers[1], w.Witnesses[1] = 0, receipt.NonInclusion{Low: 0, Next: 0, Index: 0, Path: zeros(40)}
		},
		"empty": func(w *receipt.Circuit) {
			for i := range w.Nullifiers {
				w.Nullifiers[i], w.Witnesses[i] = 0, receipt.NonInclusion{Low: 0, Next: 0, Index: 0, Path: zeros(40)}
			}
			w.Count = 0
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := fixture(t, 4, 4)
			mutate(w)
			bind(t, w)
			if err := test.IsSolved(receipt.New(4), w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("invalid receipt satisfied the circuit")
			}
		})
	}
}

// compile checks the commitment layout SPP's commitment-aware verifier expects:
// one private BSB22 commitment, no committed public inputs, two public variables.
func compile(t *testing.T, n int) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, receipt.New(n), frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	commitments := cs.GetCommitments().(constraint.Groth16Commitments)
	if len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 || cs.GetNbPublicVariables() != 2 {
		t.Fatal("receipt circuit does not match SPP's single private BSB22 commitment verifier")
	}
	return cs
}

func TestReceiptConstraints(t *testing.T) {
	if os.Getenv("RECEIPT_COUNTS") == "" {
		t.Skip("set RECEIPT_COUNTS to compile the wide shapes")
	}
	for _, n := range []int{8, 512} {
		start := time.Now()
		cs := compile(t, n)
		t.Logf("RECEIPT_COMPILE inputs=%d constraints=%d compile_ms=%d", n, cs.GetNbConstraints(), time.Since(start).Milliseconds())
	}
}

// TestReceiptProves is a real Groth16 round trip at a small shape.
func TestReceiptProves(t *testing.T) {
	if os.Getenv("RECEIPT_PROVE") == "" {
		t.Skip("set RECEIPT_PROVE for a Groth16 setup, prove and verify at shape 8")
	}
	cs := compile(t, 8)
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(fixture(t, 8, 5), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
	t.Logf("RECEIPT_PROVE inputs=8 constraints=%d prove_ms=%d", cs.GetNbConstraints(), time.Since(start).Milliseconds())
}

func hash(t *testing.T, values ...frontend.Variable) *big.Int {
	t.Helper()
	h, err := poseidon.Hash(integers(t, values))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func chain(t *testing.T, values []frontend.Variable) *big.Int {
	t.Helper()
	h, err := protocol.HashChain4(integers(t, values))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func integers(t *testing.T, values []frontend.Variable) []*big.Int {
	t.Helper()
	result := make([]*big.Int, len(values))
	for i, v := range values {
		var ok bool
		result[i], ok = new(big.Int).SetString(fmt.Sprint(v), 10)
		if !ok {
			t.Fatalf("invalid field: %v", v)
		}
	}
	return result
}

func variables(values []*big.Int) []frontend.Variable {
	result := make([]frontend.Variable, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

func zeros(n int) []frontend.Variable {
	result := make([]frontend.Variable, n)
	for i := range result {
		result[i] = 0
	}
	return result
}
