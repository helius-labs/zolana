package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type privateTxHashVector struct {
	Name              string   `json:"name"`
	InputHashes       []string `json:"input_hashes"`
	OutputHashes      []string `json:"output_hashes"`
	AddressNullifiers []string `json:"address_nullifiers"`
	Blinding          string   `json:"blinding"`
	PrivateTxHash     string   `json:"private_tx_hash"`
	ExternalDataHash  string   `json:"external_data_hash"`
	MessageHash       string   `json:"message_hash"`
}

func readPrivateTxHashVectors(t *testing.T) []privateTxHashVector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate private_tx_hash_vectors_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../../test-vectors/private_tx_hash.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []privateTxHashVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("private_tx_hash.json has no vectors")
	}
	return file.Vectors
}

func privateTxHashVectorBytes(t *testing.T, name, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil || len(out) != 32 {
		t.Fatalf("%s: %q is not 32-byte hex", name, value)
	}
	return out
}

func privateTxHashVectorFields(t *testing.T, name string, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = new(big.Int).SetBytes(privateTxHashVectorBytes(t, name, value))
	}
	return out
}

func TestPrivateTxHashMatchesSharedKnownAnswerVectors(t *testing.T) {
	for _, vector := range readPrivateTxHashVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			got, err := PrivateTxHash(
				privateTxHashVectorFields(t, vector.Name, vector.InputHashes),
				privateTxHashVectorFields(t, vector.Name, vector.OutputHashes),
				privateTxHashVectorFields(t, vector.Name, vector.AddressNullifiers),
				new(big.Int).SetBytes(privateTxHashVectorBytes(t, vector.Name, vector.Blinding)),
			)
			if err != nil {
				t.Fatal(err)
			}
			privateTxHash := got.FillBytes(make([]byte, 32))
			if hex.EncodeToString(privateTxHash) != vector.PrivateTxHash {
				t.Fatalf("private tx hash = %x, want %s", privateTxHash, vector.PrivateTxHash)
			}
			externalDataHash := privateTxHashVectorBytes(t, vector.Name, vector.ExternalDataHash)
			message := sha256.Sum256(append(privateTxHash, externalDataHash...))
			if hex.EncodeToString(message[:]) != vector.MessageHash {
				t.Fatalf("message hash = %x, want %s", message, vector.MessageHash)
			}
		})
	}
}
