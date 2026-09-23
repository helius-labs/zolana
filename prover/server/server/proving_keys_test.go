package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"zolana/prover/prover/common"
	"zolana/prover/prover/provingkeys"
)

func TestProvingKeysHandlerReportsEveryLockfileKey(t *testing.T) {
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatalf("load embedded lockfile: %v", err)
	}
	handler := provingKeysHandler{keyManager: common.NewLazyKeyManager(t.TempDir(), &common.DownloadConfig{})}

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
	if report.Prefix != manifest.Prefix {
		t.Fatalf("prefix = %q, want %q", report.Prefix, manifest.Prefix)
	}
	if len(report.Keys) != len(manifest.Keys) {
		t.Fatalf("reported %d keys, lockfile pins %d", len(report.Keys), len(manifest.Keys))
	}
	for _, key := range report.Keys {
		entry := manifest.Keys[key.Name]
		if key.ExpectedSha256 == nil || *key.ExpectedSha256 != entry.Sha256 {
			t.Fatalf("%s expectedSha256 = %v, want %s", key.Name, key.ExpectedSha256, entry.Sha256)
		}
		if key.LoadedSha256 != nil || key.Available {
			t.Fatalf("%s reported loaded or available with an empty keys dir", key.Name)
		}
	}
}

func TestProvingKeysHandlerRejectsNonGet(t *testing.T) {
	handler := provingKeysHandler{keyManager: common.NewLazyKeyManager(t.TempDir(), &common.DownloadConfig{})}
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

	got := ComputeInputHash(payload)
	if got == hex.EncodeToString(payloadOnly[:]) {
		t.Fatal("input hash ignores the proving-key version")
	}
	if got != hex.EncodeToString(versioned[:]) {
		t.Fatalf("input hash = %s, want sha256(prefix || 0 || payload)", got)
	}
}

func TestProvingKeysEndpointIsPublic(t *testing.T) {
	if requiresAuthentication("/proving-keys") {
		t.Fatal("/proving-keys requires authentication")
	}
}
