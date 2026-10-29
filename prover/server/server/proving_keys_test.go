package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

func TestProvingKeysHandlerReportsEveryLockfileKey(t *testing.T) {
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatalf("load embedded lockfile: %v", err)
	}
	handler := provingKeysHandler{}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/proving-keys", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	var report common.ProvingKeysReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(report.Keys) != len(manifest.Keys) {
		t.Fatalf("reported %d keys, lockfile pins %d", len(report.Keys), len(manifest.Keys))
	}
	zoproCount := 0
	for _, key := range report.Keys {
		entry := manifest.Keys[key.Name]
		if len(key.Artifacts) == 0 || key.Artifacts[0].Format != "gnark" || key.Artifacts[0].Sha256 != entry.Sha256 || key.Artifacts[0].Size != entry.Size {
			t.Fatalf("%s has no matching gnark download: %+v", key.Name, key.Artifacts)
		}
		for _, artifact := range key.Artifacts {
			if artifact.URL == "" {
				t.Fatalf("%s has no URL", key.Name)
			}
			if artifact.Format == "zopro" {
				zoproCount++
			}
		}
	}
	if zoproCount != 41 {
		t.Fatalf("zopro downloads = %d, want 41", zoproCount)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire) != 1 || wire["keys"] == nil {
		t.Fatalf("unexpected response fields: %s", recorder.Body.String())
	}

}

func TestProvingKeysHandlerRejectsNonGet(t *testing.T) {
	handler := provingKeysHandler{}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/proving-keys", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
}

// A cached proof from before proofs carried provingKeySha256, or from another
// key set, lives under a hash without this build's lockfile prefix, so it is
// never replayed to a client that would reject it.
func TestInputHashIncludesTheProvingKeyVersion(t *testing.T) {
	payload := json.RawMessage(`{"circuitType":"transfer-ring","nInputs":2,"nOutputs":2}`)
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatalf("load embedded lockfile: %v", err)
	}
	payloadOnly := sha256.Sum256(payload)
	versioned := sha256.Sum256(append([]byte(manifest.Prefix+"\x00"), payload...))

	got := ComputeInputHash(payload, "")
	if got == hex.EncodeToString(payloadOnly[:]) {
		t.Fatal("input hash ignores the proving-key version")
	}
	if got != hex.EncodeToString(versioned[:]) {
		t.Fatalf("input hash = %s, want sha256(prefix || 0 || payload)", got)
	}
}

func TestProvingKeysEndpointIsPublic(t *testing.T) {
	for _, path := range []string{"/proving-keys", gatewayPrefix + "/proving-keys"} {
		if requiresAuthentication(path) {
			t.Fatalf("%s requires authentication", path)
		}
	}
}
