package common

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func entryFor(data []byte) lockEntry {
	return lockEntry{Sha256: sha256Hex(data), Size: int64(len(data))}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func testDownloadConfig(maxRetries int) *DownloadConfig {
	return &DownloadConfig{
		MaxRetries:    maxRetries,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: time.Millisecond,
		AutoDownload:  true,
	}
}

// useTestManifest installs a synthetic manifest for the duration of a test so the
// lookup logic in EnsureProvingKey can be exercised without the real 133-key
// embedded lockfile, then restores production behavior on cleanup.
func useTestManifest(t *testing.T, m *lockManifest) {
	t.Helper()
	old := manifestForTest
	manifestForTest = m
	t.Cleanup(func() { manifestForTest = old })
}

// countingServer serves fixed bodies per URL path and records request counts,
// so tests can assert both correct content and no-network / fail-fast behavior.
type countingServer struct {
	mu       sync.Mutex
	bodies   map[string][]byte
	statuses map[string][]int
	counts   map[string]int
}

func newCountingServer() *countingServer {
	return &countingServer{
		bodies:   map[string][]byte{},
		statuses: map[string][]int{},
		counts:   map[string]int{},
	}
}

func (s *countingServer) setBody(path string, body []byte) {
	s.mu.Lock()
	s.bodies[path] = body
	s.mu.Unlock()
}

func (s *countingServer) setStatuses(path string, statuses ...int) {
	s.mu.Lock()
	s.statuses[path] = append([]int(nil), statuses...)
	s.mu.Unlock()
}

func (s *countingServer) requests(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[path]
}

func (s *countingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.counts[r.URL.Path]++
	count := s.counts[r.URL.Path]
	statuses := s.statuses[r.URL.Path]
	body, ok := s.bodies[r.URL.Path]
	s.mu.Unlock()

	if len(statuses) > 0 {
		idx := count - 1
		if idx >= len(statuses) {
			idx = len(statuses) - 1
		}
		if status := statuses[idx]; status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}
	}

	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := w.Write(body); err != nil {
		panic(err)
	}
}

func TestDownloadAndVerifySuccess(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "success.key")
	body := []byte("a downloaded proving key")

	server := newCountingServer()
	server.setBody("/success.key", body)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	url := httpServer.URL + "/success.key"
	if err := downloadAndVerify(url, keyPath, entryFor(body), testDownloadConfig(1)); err != nil {
		t.Fatalf("downloadAndVerify: %v", err)
	}
	if got := readTestFile(t, keyPath); !bytes.Equal(got, body) {
		t.Fatalf("downloaded file = %q, want %q", got, body)
	}
	if _, statErr := os.Stat(keyPath + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("temp file still present or unexpected stat error: %v", statErr)
	}
	if got := server.requests("/success.key"); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestDownloadAndVerifyShaMismatch(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "mismatch.key")
	body := []byte("actual bytes")
	// Correct size, wrong sha256 -> the sha check must fail.
	entry := lockEntry{Sha256: sha256Hex([]byte("different bytes here!")), Size: int64(len(body))}

	server := newCountingServer()
	server.setBody("/mismatch.key", body)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	err := downloadAndVerify(httpServer.URL+"/mismatch.key", keyPath, entry, testDownloadConfig(1))
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("error = %v, want sha256 mismatch", err)
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("key file left behind or unexpected stat error: %v", statErr)
	}
	if _, statErr := os.Stat(keyPath + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("temp file left behind or unexpected stat error: %v", statErr)
	}
}

func TestDownloadAndVerifySizeMismatch(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "size.key")
	body := []byte("twelve bytes")
	// Correct sha256, wrong size -> the size check must fail first.
	entry := lockEntry{Sha256: sha256Hex(body), Size: int64(len(body)) + 1}

	server := newCountingServer()
	server.setBody("/size.key", body)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	err := downloadAndVerify(httpServer.URL+"/size.key", keyPath, entry, testDownloadConfig(1))
	if err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("error = %v, want size mismatch", err)
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("key file left behind or unexpected stat error: %v", statErr)
	}
}

func TestDownloadAndVerify404FailsFast(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "missing.key")

	server := newCountingServer()
	server.setStatuses("/missing.key", http.StatusNotFound)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	err := downloadAndVerify(httpServer.URL+"/missing.key", keyPath, lockEntry{Sha256: "deadbeef", Size: 1}, testDownloadConfig(3))
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("error = %v, want HTTP 404", err)
	}
	if got := server.requests("/missing.key"); got != 1 {
		t.Fatalf("requests = %d, want 1 (permanent 4xx fails fast)", got)
	}
}

func TestDownloadAndVerifyRetriesThenSucceeds(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "retry.key")
	body := []byte("eventually served")

	server := newCountingServer()
	server.setBody("/retry.key", body)
	server.setStatuses("/retry.key", http.StatusInternalServerError, http.StatusOK)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	if err := downloadAndVerify(httpServer.URL+"/retry.key", keyPath, entryFor(body), testDownloadConfig(3)); err != nil {
		t.Fatalf("downloadAndVerify: %v", err)
	}
	if got := readTestFile(t, keyPath); !bytes.Equal(got, body) {
		t.Fatalf("downloaded file = %q, want %q", got, body)
	}
	if got := server.requests("/retry.key"); got != 2 {
		t.Fatalf("requests = %d, want 2 (500 then 200)", got)
	}
}

func TestEnsureProvingKeyCacheHitSkipsNetwork(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "cached.key")
	body := []byte("already on disk")
	writeTestFile(t, keyPath, body)

	useTestManifest(t, &lockManifest{
		Prefix: "proving-keys",
		Keys:   map[string]lockEntry{"cached.key": entryFor(body)},
	})

	server := newCountingServer()
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	t.Setenv(provingKeysURLEnvVar, httpServer.URL)

	if err := EnsureProvingKey(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("EnsureProvingKey: %v", err)
	}
	if got := server.requests("/proving-keys/cached.key"); got != 0 {
		t.Fatalf("requests = %d, want 0 (cache hit)", got)
	}
}

func TestEnsureProvingKeyNotInManifestPresentIsOK(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "local-only.key")
	writeTestFile(t, keyPath, []byte("locally generated"))

	useTestManifest(t, &lockManifest{Prefix: "proving-keys", Keys: map[string]lockEntry{}})

	if err := EnsureProvingKey(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("EnsureProvingKey: %v", err)
	}
}

func TestEnsureProvingKeyNotInManifestMissingErrors(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "local-only.key")

	useTestManifest(t, &lockManifest{Prefix: "proving-keys", Keys: map[string]lockEntry{}})

	err := EnsureProvingKey(keyPath, true, testDownloadConfig(1))
	if err == nil || !strings.Contains(err.Error(), "not in the proving-keys lockfile") {
		t.Fatalf("error = %v, want not-in-lockfile error", err)
	}
}

func TestEnsureProvingKeyDownloadsMissingKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "download.key")
	body := []byte("fetched from the object store")

	useTestManifest(t, &lockManifest{
		Prefix: "proving-keys",
		Keys:   map[string]lockEntry{"download.key": entryFor(body)},
	})

	server := newCountingServer()
	server.setBody("/proving-keys/download.key", body)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	t.Setenv(provingKeysURLEnvVar, httpServer.URL)

	if err := EnsureProvingKey(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("EnsureProvingKey: %v", err)
	}
	if got := readTestFile(t, keyPath); !bytes.Equal(got, body) {
		t.Fatalf("downloaded file = %q, want %q", got, body)
	}
	if got := server.requests("/proving-keys/download.key"); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestEnsureProvingKeyAutoDownloadDisabled(t *testing.T) {
	body := []byte("pinned bytes")
	manifest := &lockManifest{
		Prefix: "proving-keys",
		Keys:   map[string]lockEntry{"pinned.key": entryFor(body)},
	}

	t.Run("missing file errors", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "pinned.key")
		useTestManifest(t, manifest)

		err := EnsureProvingKey(keyPath, false, testDownloadConfig(1))
		if err == nil || !strings.Contains(err.Error(), "required key file not found") {
			t.Fatalf("error = %v, want missing-file error", err)
		}
	})

	t.Run("mismatched file errors and is not removed", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "pinned.key")
		writeTestFile(t, keyPath, []byte("wrong bytes"))
		useTestManifest(t, manifest)

		err := EnsureProvingKey(keyPath, false, testDownloadConfig(1))
		if err == nil || !strings.Contains(err.Error(), "does not match the lockfile checksum") {
			t.Fatalf("error = %v, want checksum mismatch error", err)
		}
		if _, statErr := os.Stat(keyPath); statErr != nil {
			t.Fatalf("mismatched file was removed or stat failed: %v", statErr)
		}
	})
}

func TestEnsureProvingKeyReplacesMismatchedFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "stale.key")
	writeTestFile(t, keyPath, []byte("stale contents"))
	body := []byte("fresh verified contents")

	useTestManifest(t, &lockManifest{
		Prefix: "proving-keys",
		Keys:   map[string]lockEntry{"stale.key": entryFor(body)},
	})

	server := newCountingServer()
	server.setBody("/proving-keys/stale.key", body)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	t.Setenv(provingKeysURLEnvVar, httpServer.URL)

	if err := EnsureProvingKey(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("EnsureProvingKey: %v", err)
	}
	if got := readTestFile(t, keyPath); !bytes.Equal(got, body) {
		t.Fatalf("file after re-download = %q, want %q", got, body)
	}
}

func TestBaseURL(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv(provingKeysURLEnvVar, "")
		if got := baseURL(); got != defaultProvingKeysBaseURL {
			t.Fatalf("baseURL = %q, want %q", got, defaultProvingKeysBaseURL)
		}
	})
	t.Run("override trims trailing slash", func(t *testing.T) {
		t.Setenv(provingKeysURLEnvVar, "https://mirror.example.com/keys/")
		if got := baseURL(); got != "https://mirror.example.com/keys" {
			t.Fatalf("baseURL = %q, want trimmed override", got)
		}
	})
}

func TestObjectURL(t *testing.T) {
	t.Setenv(provingKeysURLEnvVar, "https://mirror.example.com")
	if got := objectURL("proving-keys", "v2_inclusion_32_1.key"); got != "https://mirror.example.com/proving-keys/v2_inclusion_32_1.key" {
		t.Fatalf("objectURL = %q", got)
	}
	if got := objectURL("", "bare.key"); got != "https://mirror.example.com/bare.key" {
		t.Fatalf("objectURL with empty prefix = %q", got)
	}
}

func TestEmbeddedManifestLoads(t *testing.T) {
	// Ensure the real embedded lockfile is used, not any test seam.
	old := manifestForTest
	manifestForTest = nil
	t.Cleanup(func() { manifestForTest = old })

	m, err := loadManifest()
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	if !strings.HasPrefix(m.Prefix, "proving-keys/") {
		t.Fatalf("prefix = %q, want proving-keys/<version-hash>", m.Prefix)
	}
	if len(m.Keys) == 0 {
		t.Fatalf("embedded manifest has no keys")
	}
	for name, entry := range m.Keys {
		if len(entry.Sha256) != 64 {
			t.Fatalf("key %s sha256 = %q, want 64 hex chars", name, entry.Sha256)
		}
		if entry.Size <= 0 {
			t.Fatalf("key %s size = %d, want > 0", name, entry.Size)
		}
	}
}
