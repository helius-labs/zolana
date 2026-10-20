package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type ringSpendMessageVector struct {
	Prefix           string `json:"prefix"`
	RingProgramID    string `json:"ring_program_id"`
	PrivateTxHash    string `json:"private_tx_hash"`
	ExternalDataHash string `json:"external_data_hash"`
	Digest           string `json:"digest"`
	Message          string `json:"message"`
	Seed             string `json:"seed"`
	PublicKey        string `json:"public_key"`
	Signature        string `json:"signature"`
}

func readRingSpendMessageVector(t *testing.T) ringSpendMessageVector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate ring_spend_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../../test-vectors/ring_spend_message.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector ringSpendMessageVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func ringSpendVectorBytes(t *testing.T, name, value string, length int) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil || len(out) != length {
		t.Fatalf("%s: %q is not %d-byte hex", name, value, length)
	}
	return out
}

func TestRingSpendMessageMatchesSharedKnownAnswerVector(t *testing.T) {
	vector := readRingSpendMessageVector(t)
	if vector.Prefix != string(RingSpendMessagePrefix) {
		t.Fatalf("prefix = %q, want %q", RingSpendMessagePrefix, vector.Prefix)
	}
	ring := [32]byte(ringSpendVectorBytes(t, "ring_program_id", vector.RingProgramID, 32))
	privateTxHash := ringSpendVectorBytes(t, "private_tx_hash", vector.PrivateTxHash, 32)
	externalDataHash := ringSpendVectorBytes(t, "external_data_hash", vector.ExternalDataHash, 32)
	digest := sha256.Sum256(append(privateTxHash, externalDataHash...))
	if hex.EncodeToString(digest[:]) != vector.Digest {
		t.Fatalf("digest = %x, want %s", digest, vector.Digest)
	}
	message := RingSpendMessage(ring, digest)
	if !bytes.Equal(message, ringSpendVectorBytes(t, "message", vector.Message, len(RingSpendMessagePrefix)+64)) {
		t.Fatalf("message = %x, want %s", message, vector.Message)
	}
	key := ed25519.NewKeyFromSeed(ringSpendVectorBytes(t, "seed", vector.Seed, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	if hex.EncodeToString(publicKey) != vector.PublicKey {
		t.Fatalf("public key = %x, want %s", publicKey, vector.PublicKey)
	}
	signature := ringSpendVectorBytes(t, "signature", vector.Signature, ed25519.SignatureSize)
	if !bytes.Equal(ed25519.Sign(key, message), signature) {
		t.Fatal("the committed signature is not the deterministic signature over the message")
	}
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("the committed signature does not verify")
	}
}
