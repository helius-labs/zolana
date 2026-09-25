package common

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func writeTempKey(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write temp key: %v", err)
	}
	return path
}

func TestReadKeyFileHashesTheWholeFile(t *testing.T) {
	// More than one read-buffer's worth, so the digest spans several reads.
	contents := bytes.Repeat([]byte("zolana-proving-key"), 100_000)
	path := writeTempKey(t, contents)

	// The deserializer consumes only a prefix; the digest must still cover the
	// trailing bytes, as the lockfile sha256 does.
	var consumed []byte
	digest, err := readKeyFile(path, func(r io.Reader) (int64, error) {
		consumed = make([]byte, 1024)
		n, err := io.ReadFull(r, consumed)
		return int64(n), err
	})
	if err != nil {
		t.Fatalf("readKeyFile: %v", err)
	}
	if !bytes.Equal(consumed, contents[:1024]) {
		t.Fatal("deserializer did not see the file prefix")
	}
	if digest != sha256.Sum256(contents) {
		t.Fatalf("digest = %x, want sha256 of the whole file", digest)
	}
}

func TestReadKeyFilePropagatesReadErrors(t *testing.T) {
	path := writeTempKey(t, []byte("short"))
	wantErr := errors.New("malformed key")
	_, err := readKeyFile(path, func(io.Reader) (int64, error) { return 0, wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if _, err := readKeyFile(filepath.Join(t.TempDir(), "missing.key"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file err = %v, want os.ErrNotExist", err)
	}
}

func testProof() groth16bn254.Proof {
	_, _, g1, g2 := bn254.Generators()
	return groth16bn254.Proof{Ar: g1, Bs: g2, Krs: g1}
}

func TestProofJSONCarriesProvingKeySha256(t *testing.T) {
	digest := sha256.Sum256([]byte("transfer_ring_2_2.key"))
	proof := testProof()
	encoded, err := json.Marshal(&Proof{Proof: &proof, ProvingKeySha256: digest})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire ProofJSON
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("decode wire json: %v", err)
	}
	if wire.ProvingKeySha256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("provingKeySha256 = %q, want %x", wire.ProvingKeySha256, digest)
	}

	// The Redis queue stores and rereads proofs, so the digest must survive.
	var decoded Proof
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ProvingKeySha256 != digest {
		t.Fatalf("decoded digest = %x, want %x", decoded.ProvingKeySha256, digest)
	}
}

func TestProofJSONOmitsUnknownProvingKeySha256(t *testing.T) {
	proof := testProof()
	encoded, err := json.Marshal(&Proof{Proof: &proof})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "provingKeySha256") {
		t.Fatalf("zero digest was serialized: %s", encoded)
	}
	decoded := Proof{ProvingKeySha256: sha256.Sum256([]byte("stale"))}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.ProvingKeySha256 != ([32]byte{}) {
		t.Fatalf("decoded digest = %x, want zero", decoded.ProvingKeySha256)
	}
}

func TestProofJSONRejectsMalformedProvingKeySha256(t *testing.T) {
	proof := testProof()
	encoded, err := json.Marshal(&Proof{Proof: &proof})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, bad := range []string{"zz", strings.Repeat("ab", 31), strings.Repeat("ab", 33), strings.Repeat("g", 64)} {
		var wire map[string]any
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatalf("decode wire json: %v", err)
		}
		wire["provingKeySha256"] = bad
		tampered, err := json.Marshal(wire)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		var decoded Proof
		if err := json.Unmarshal(tampered, &decoded); err == nil {
			t.Fatalf("provingKeySha256 %q was accepted", bad)
		}
	}
}
