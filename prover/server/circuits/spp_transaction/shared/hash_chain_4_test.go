package shared_test

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"zolana/prover/circuits/gadget"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type hashChain4Circuit struct {
	Inputs []frontend.Variable
	Hash   frontend.Variable `gnark:",public"`
}

func (c *hashChain4Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Hash, gadget.HashChain4(api, c.Inputs))
	return nil
}

type hashChain4Vector struct {
	Name   string   `json:"name"`
	Inputs []string `json:"inputs"`
	Output string   `json:"output"`
}

func readHashChain4Vectors(t *testing.T) []hashChain4Vector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate hash_chain_4_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../../test-vectors/hash_chain_4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []hashChain4Vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return file.Vectors
}

func parseHashChain4Hex(t *testing.T, name, value string) *big.Int {
	t.Helper()
	out, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("%s: %q is not hex", name, value)
	}
	return out
}

func TestHashChain4GadgetMatchesSharedKnownAnswerVectors(t *testing.T) {
	for _, vector := range readHashChain4Vectors(t) {
		if len(vector.Inputs) == 0 {
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			length := len(vector.Inputs)
			want := parseHashChain4Hex(t, vector.Name, vector.Output)
			host, err := protocol.HashChain4(parseHashChain4Inputs(t, vector))
			if err != nil {
				t.Fatal(err)
			}
			if host.Cmp(want) != 0 {
				t.Fatalf("host hash = %064x, want %064x", host, want)
			}
			circuit := &hashChain4Circuit{Inputs: make([]frontend.Variable, length)}
			assignment := &hashChain4Circuit{Inputs: make([]frontend.Variable, length), Hash: want}
			for i, input := range vector.Inputs {
				assignment.Inputs[i] = parseHashChain4Hex(t, vector.Name, input)
			}
			assert := test.NewAssert(t)
			assert.CheckCircuit(circuit,
				test.WithValidAssignment(assignment),
				test.WithCurves(ecc.BN254),
				test.NoFuzzing(),
				test.NoSerializationChecks(),
			)
		})
	}
}

func TestHashChain4GadgetRejectsBinaryChain(t *testing.T) {
	inputs := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	binary, err := protocol.HashChain(inputs)
	if err != nil {
		t.Fatal(err)
	}
	circuit := &hashChain4Circuit{Inputs: make([]frontend.Variable, len(inputs))}
	assignment := &hashChain4Circuit{Inputs: make([]frontend.Variable, len(inputs)), Hash: binary}
	for i, input := range inputs {
		assignment.Inputs[i] = input
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit,
		test.WithInvalidAssignment(assignment),
		test.WithCurves(ecc.BN254),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
	)
}

func parseHashChain4Inputs(t *testing.T, vector hashChain4Vector) []*big.Int {
	t.Helper()
	inputs := make([]*big.Int, len(vector.Inputs))
	for i, input := range vector.Inputs {
		inputs[i] = parseHashChain4Hex(t, vector.Name, input)
	}
	return inputs
}
