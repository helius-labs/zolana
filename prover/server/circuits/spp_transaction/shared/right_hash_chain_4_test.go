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

type rightHashChain4Circuit struct {
	Inputs []frontend.Variable
	Hash   frontend.Variable `gnark:",public"`
}

func (c *rightHashChain4Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Hash, gadget.RightHashChain4(api, c.Inputs))
	return nil
}

type rightHashChain4Vector struct {
	Name   string   `json:"name"`
	Inputs []string `json:"inputs"`
	Output string   `json:"output"`
}

func readRightHashChain4Vectors(t *testing.T) []rightHashChain4Vector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate right_hash_chain_4_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../../test-vectors/right_hash_chain_4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []rightHashChain4Vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return file.Vectors
}

func parseRightHashChain4Hex(t *testing.T, name, value string) *big.Int {
	t.Helper()
	out, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("%s: %q is not hex", name, value)
	}
	return out
}

func parseRightHashChain4Inputs(t *testing.T, vector rightHashChain4Vector) []*big.Int {
	t.Helper()
	inputs := make([]*big.Int, len(vector.Inputs))
	for i, input := range vector.Inputs {
		inputs[i] = parseRightHashChain4Hex(t, vector.Name, input)
	}
	return inputs
}

// The gadget, the host mirror and the Rust definition must all agree on the
// committed bytes: this is the cached-commitment chain's cross-language pin.
func TestRightHashChain4GadgetMatchesSharedKnownAnswerVectors(t *testing.T) {
	for _, vector := range readRightHashChain4Vectors(t) {
		if len(vector.Inputs) == 0 {
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			length := len(vector.Inputs)
			want := parseRightHashChain4Hex(t, vector.Name, vector.Output)
			host, err := protocol.RightHashChain4(parseRightHashChain4Inputs(t, vector))
			if err != nil {
				t.Fatal(err)
			}
			if host.Cmp(want) != 0 {
				t.Fatalf("host hash = %064x, want %064x", host, want)
			}
			circuit := &rightHashChain4Circuit{Inputs: make([]frontend.Variable, length)}
			assignment := &rightHashChain4Circuit{Inputs: make([]frontend.Variable, length), Hash: want}
			for i, input := range vector.Inputs {
				assignment.Inputs[i] = parseRightHashChain4Hex(t, vector.Name, input)
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

// A proof built against the left fold must not satisfy the right one. Four
// elements are the one length where both folds are the same single call, so
// the rejection is checked at five.
func TestRightHashChain4GadgetRejectsTheLeftFold(t *testing.T) {
	inputs := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}
	left, err := protocol.HashChain4(inputs)
	if err != nil {
		t.Fatal(err)
	}
	circuit := &rightHashChain4Circuit{Inputs: make([]frontend.Variable, len(inputs))}
	assignment := &rightHashChain4Circuit{Inputs: make([]frontend.Variable, len(inputs)), Hash: left}
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
