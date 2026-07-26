package gadget

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type hashBytesCircuit struct {
	Bytes    [63]frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *hashBytesCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(HashBytes(api, c.Bytes[:]), c.Expected)
	return nil
}

func TestHashBytesMatchesSharedKnownAnswerVector(t *testing.T) {
	type vector struct {
		Name   string `json:"name"`
		Input  string `json:"input"`
		Output string `json:"output"`
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate hash_bytes_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../test-vectors/hash_bytes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	var selected vector
	for _, candidate := range vectors {
		if candidate.Name == "three_chunk_boundary" {
			selected = candidate
			break
		}
	}
	bytes, err := hex.DecodeString(selected.Input)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes) != 63 {
		t.Fatalf("three_chunk_boundary has %d bytes", len(bytes))
	}
	var assignment hashBytesCircuit
	for i := range bytes {
		assignment.Bytes[i] = bytes[i]
	}
	expected, ok := new(big.Int).SetString(selected.Output, 16)
	if !ok {
		t.Fatal("three_chunk_boundary output is not hex")
	}
	assignment.Expected = expected
	if err := test.IsSolved(&hashBytesCircuit{}, &assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}
