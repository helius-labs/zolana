package protocol

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"zolana/prover/prover-test/poseidon"
)

func TestHashBytesSemantics(t *testing.T) {
	empty, err := HashBytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Sign() != 0 {
		t.Fatalf("empty hash = %s, want 0", empty)
	}

	oneChunk := make([]byte, 31)
	for i := range oneChunk {
		oneChunk[i] = byte(i + 1)
	}
	got, err := HashBytes(oneChunk)
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).SetBytes(oneChunk)
	if got.Cmp(want) != 0 {
		t.Fatalf("single chunk = %s, want packed value %s", got, want)
	}

	input := append(append([]byte{}, oneChunk...), 0xaa, 0xbb)
	got, err = HashBytes(input)
	if err != nil {
		t.Fatal(err)
	}
	want, err = poseidon.Hash([]*big.Int{new(big.Int).SetBytes(oneChunk), big.NewInt(0xaabb)})
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("multi-chunk hash = %s, want %s", got, want)
	}
}

func TestHashBytesSharedKnownAnswerVectors(t *testing.T) {
	type vector struct {
		Name   string `json:"name"`
		Input  string `json:"input"`
		Output string `json:"output"`
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate hash_bytes_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../../test-vectors/hash_bytes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		input, err := hex.DecodeString(vector.Input)
		if err != nil {
			t.Fatalf("%s input: %v", vector.Name, err)
		}
		output, err := HashBytes(input)
		if err != nil {
			t.Fatalf("%s hash: %v", vector.Name, err)
		}
		expected, ok := new(big.Int).SetString(vector.Output, 16)
		if !ok {
			t.Fatalf("%s output is not hex", vector.Name)
		}
		if output.Cmp(expected) != 0 {
			t.Fatalf("%s = %064x, want %064x", vector.Name, output, expected)
		}
	}
}
