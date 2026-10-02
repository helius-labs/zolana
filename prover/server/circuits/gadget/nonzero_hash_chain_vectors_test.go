package gadget

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type nonZeroHashChainVector struct {
	Name   string   `json:"name"`
	Inputs []string `json:"inputs"`
	Output string   `json:"output"`
}

func readNonZeroHashChainVectors(t *testing.T) []nonZeroHashChainVector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate nonzero_hash_chain_vectors_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../test-vectors/nonzero_hash_chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []nonZeroHashChainVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return file.Vectors
}

func parseNonZeroHashChainHex(t *testing.T, name, value string) *big.Int {
	t.Helper()
	out, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("%s: %q is not hex", name, value)
	}
	return out
}

func TestNonZeroHashChainMatchesSharedKnownAnswerVectors(t *testing.T) {
	for _, vector := range readNonZeroHashChainVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			inputs := make([]*big.Int, len(vector.Inputs))
			for i, input := range vector.Inputs {
				inputs[i] = parseNonZeroHashChainHex(t, vector.Name, input)
			}
			want := parseNonZeroHashChainHex(t, vector.Name, vector.Output)
			host, err := protocol.NonZeroHashChain(inputs)
			if err != nil {
				t.Fatal(err)
			}
			if host.Cmp(want) != 0 {
				t.Fatalf("host hash = %064x, want %064x", host, want)
			}
			circuit := &nonZeroHashChainCircuit{Inputs: make([]frontend.Variable, len(inputs))}
			if err := test.IsSolved(circuit, nonZeroHashChainAssignment(inputs, want), ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("gadget differs from the committed vector: %v", err)
			}
		})
	}
}
