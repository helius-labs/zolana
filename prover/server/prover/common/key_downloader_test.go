package common

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testReleaseServer struct {
	mu            sync.Mutex
	assets        []releaseAsset
	assetBodies   map[int64][]byte
	assetStatuses map[int64][]int
	releaseCount  int
	assetCounts   map[int64]int
	releaseTags   []string
	authHeaders   []string
}

func newTestReleaseServer(_ *testing.T, assets []releaseAsset, assetBodies map[int64][]byte) *testReleaseServer {
	s := &testReleaseServer{
		assets:        append([]releaseAsset(nil), assets...),
		assetBodies:   assetBodies,
		assetStatuses: map[int64][]int{},
		assetCounts:   map[int64]int{},
	}
	return s
}

func (s *testReleaseServer) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	s.handle(recorder, req)
	resp := recorder.Result()
	resp.Request = req
	return resp, nil
}

func (s *testReleaseServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	releasePrefix := "/repos/" + ProvingKeysRepo + "/releases/tags/"
	if strings.HasPrefix(r.URL.Path, releasePrefix) {
		tag := strings.TrimPrefix(r.URL.Path, releasePrefix)
		s.mu.Lock()
		s.releaseCount++
		s.releaseTags = append(s.releaseTags, tag)
		s.authHeaders = append(s.authHeaders, r.Header.Get("Authorization"))
		assets := append([]releaseAsset(nil), s.assets...)
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(struct {
			Assets []releaseAsset `json:"assets"`
		}{Assets: assets})
		if err != nil {
			panic(fmt.Sprintf("encode release response: %v", err))
		}
		return
	}

	assetPrefix := "/repos/" + ProvingKeysRepo + "/releases/assets/"
	if strings.HasPrefix(r.URL.Path, assetPrefix) {
		idText := strings.TrimPrefix(r.URL.Path, assetPrefix)
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil {
			http.Error(w, "bad asset id", http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		s.assetCounts[id]++
		count := s.assetCounts[id]
		s.authHeaders = append(s.authHeaders, r.Header.Get("Authorization"))
		statuses := append([]int(nil), s.assetStatuses[id]...)
		body, ok := s.assetBodies[id]
		s.mu.Unlock()

		if !ok {
			http.Error(w, "missing asset", http.StatusNotFound)
			return
		}

		status := http.StatusOK
		if len(statuses) > 0 {
			idx := count - 1
			if idx >= len(statuses) {
				idx = len(statuses) - 1
			}
			status = statuses[idx]
		}
		if status != http.StatusOK {
			http.Error(w, fmt.Sprintf("status %d", status), status)
			return
		}

		if _, err := w.Write(body); err != nil {
			panic(fmt.Sprintf("write asset response: %v", err))
		}
		return
	}

	http.NotFound(w, r)
}

func (s *testReleaseServer) setAssetStatuses(id int64, statuses ...int) {
	s.mu.Lock()
	s.assetStatuses[id] = append([]int(nil), statuses...)
	s.mu.Unlock()
}

func (s *testReleaseServer) requestsForAsset(id int64) int {
	s.mu.Lock()
	count := s.assetCounts[id]
	s.mu.Unlock()
	return count
}

func (s *testReleaseServer) requestsForRelease() int {
	s.mu.Lock()
	count := s.releaseCount
	s.mu.Unlock()
	return count
}

func (s *testReleaseServer) sawReleaseTag(tag string) bool {
	s.mu.Lock()
	tags := append([]string(nil), s.releaseTags...)
	s.mu.Unlock()
	for _, got := range tags {
		if got == tag {
			return true
		}
	}
	return false
}

func (s *testReleaseServer) sawAuthorization(header string) bool {
	s.mu.Lock()
	headers := append([]string(nil), s.authHeaders...)
	s.mu.Unlock()
	for _, got := range headers {
		if got == header {
			return true
		}
	}
	return false
}

func useTestGitHub(t *testing.T, s *testReleaseServer) {
	oldBaseURL := githubAPIBaseURL
	oldMetadataClient := metadataHTTPClient
	oldAssetClient := assetHTTPClient
	checksumMergeMu.Lock()
	oldChecksumStates := checksumMergeStates
	checksumMergeStates = map[string]*checksumMergeState{}
	checksumMergeMu.Unlock()

	githubAPIBaseURL = "https://api.github.test"
	metadataHTTPClient = &http.Client{Transport: s}
	assetHTTPClient = &http.Client{Transport: s}

	t.Cleanup(func() {
		githubAPIBaseURL = oldBaseURL
		metadataHTTPClient = oldMetadataClient
		assetHTTPClient = oldAssetClient
		checksumMergeMu.Lock()
		checksumMergeStates = oldChecksumStates
		checksumMergeMu.Unlock()
	})
}

func testDownloadConfig(maxRetries int) *DownloadConfig {
	return &DownloadConfig{
		MaxRetries:    maxRetries,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: time.Millisecond,
		AutoDownload:  true,
	}
}

func checksumHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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

func writeTestChecksum(t *testing.T, dir string, entries map[string]string) {
	t.Helper()
	var b strings.Builder
	for name, sum := range entries {
		if _, err := fmt.Fprintf(&b, "%s  %s\n", sum, name); err != nil {
			t.Fatalf("format checksum entry: %v", err)
		}
	}
	writeTestFile(t, filepath.Join(dir, "CHECKSUM"), []byte(b.String()))
}

func releaseWithChecksumAndKey(filename string, body []byte) ([]releaseAsset, map[int64][]byte) {
	checksum := []byte(fmt.Sprintf("%s  %s\n", checksumHex(body), filename))
	return []releaseAsset{
			{ID: 1, Name: "CHECKSUM"},
			{ID: 2, Name: filename},
		}, map[int64][]byte{
			1: checksum,
			2: body,
		}
}

func TestEnsureProvingKeyLocalChecksumVerifiedSkipsNetwork(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "local.key")
	keyBody := []byte("local key")
	writeTestFile(t, keyPath, keyBody)
	writeTestChecksum(t, dir, map[string]string{"local.key": checksumHex(keyBody)})

	server := newTestReleaseServer(t, nil, nil)
	useTestGitHub(t, server)

	if err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("ensure local key: %v", err)
	}
	if got := server.requestsForRelease(); got != 0 {
		t.Fatalf("release requests = %d, want 0", got)
	}
}

func TestEnsureProvingKeyAutoDownloadDisabled(t *testing.T) {
	t.Run("missing file errors without network", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "missing.key")
		server := newTestReleaseServer(t, nil, nil)
		useTestGitHub(t, server)

		err := EnsureProvingKeyFromRelease(keyPath, false, testDownloadConfig(1))
		if err == nil || !strings.Contains(err.Error(), "required key file not found") {
			t.Fatalf("error = %v, want missing-file error", err)
		}
		if got := server.requestsForRelease(); got != 0 {
			t.Fatalf("release requests = %d, want 0", got)
		}
	})

	t.Run("checksum failure errors without network", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "bad.key")
		writeTestFile(t, keyPath, []byte("bad key"))
		writeTestChecksum(t, dir, map[string]string{"bad.key": checksumHex([]byte("expected key"))})
		server := newTestReleaseServer(t, nil, nil)
		useTestGitHub(t, server)

		err := EnsureProvingKeyFromRelease(keyPath, false, testDownloadConfig(1))
		if err == nil || !strings.Contains(err.Error(), "failed checksum verification") {
			t.Fatalf("error = %v, want checksum verification error", err)
		}
		if got := server.requestsForRelease(); got != 0 {
			t.Fatalf("release requests = %d, want 0", got)
		}
	})
}

func TestEnsureProvingKeyExactAssetDownload(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "exact.key")
	keyBody := []byte("downloaded exact key")
	assets, bodies := releaseWithChecksumAndKey("exact.key", keyBody)
	server := newTestReleaseServer(t, assets, bodies)
	useTestGitHub(t, server)

	if err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("ensure exact key: %v", err)
	}
	if got := readTestFile(t, keyPath); !bytes.Equal(got, keyBody) {
		t.Fatalf("downloaded file = %q, want %q", got, keyBody)
	}
	if got := server.requestsForAsset(1); got != 1 {
		t.Fatalf("CHECKSUM requests = %d, want 1", got)
	}
	if got := server.requestsForAsset(2); got != 1 {
		t.Fatalf("key requests = %d, want 1", got)
	}
}

func TestEnsureProvingKeySplitAssetDownload(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "split.key")
	partA := []byte("left-")
	partB := []byte("right")
	keyBody := append(append([]byte(nil), partA...), partB...)
	checksum := []byte(fmt.Sprintf("%s  split.key\n", checksumHex(keyBody)))
	server := newTestReleaseServer(t, []releaseAsset{
		{ID: 1, Name: "CHECKSUM"},
		{ID: 2, Name: "split.key.part-000"},
		{ID: 3, Name: "split.key.part-001"},
	}, map[int64][]byte{
		1: checksum,
		2: partA,
		3: partB,
	})
	useTestGitHub(t, server)

	if err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("ensure split key: %v", err)
	}
	if got := readTestFile(t, keyPath); !bytes.Equal(got, keyBody) {
		t.Fatalf("assembled file = %q, want %q", got, keyBody)
	}
	if got := server.requestsForAsset(2); got != 1 {
		t.Fatalf("part 000 requests = %d, want 1", got)
	}
	if got := server.requestsForAsset(3); got != 1 {
		t.Fatalf("part 001 requests = %d, want 1", got)
	}
	for _, partName := range []string{"split.key.part-000", "split.key.part-001"} {
		partPath := filepath.Join(dir, partName)
		if _, statErr := os.Stat(partPath); !os.IsNotExist(statErr) {
			t.Fatalf("split part %s still exists or stat failed with unexpected error: %v", partName, statErr)
		}
	}
}

func TestEnsureProvingKeyChecksumMismatchRemovesFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "mismatch.key")
	keyBody := []byte("actual key")
	checksum := []byte(fmt.Sprintf("%s  mismatch.key\n", checksumHex([]byte("expected key"))))
	server := newTestReleaseServer(t, []releaseAsset{
		{ID: 1, Name: "CHECKSUM"},
		{ID: 2, Name: "mismatch.key"},
	}, map[int64][]byte{
		1: checksum,
		2: keyBody,
	})
	useTestGitHub(t, server)

	err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(1))
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want checksum mismatch", err)
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("downloaded file still exists or stat failed with unexpected error: %v", statErr)
	}
}

func TestDownloadAssetRetries(t *testing.T) {
	t.Run("404 fails fast", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "not-found.key")
		keyBody := []byte("key")
		assets, bodies := releaseWithChecksumAndKey("not-found.key", keyBody)
		server := newTestReleaseServer(t, assets, bodies)
		server.setAssetStatuses(2, http.StatusNotFound)
		useTestGitHub(t, server)

		err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(3))
		if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
			t.Fatalf("error = %v, want HTTP 404", err)
		}
		if got := server.requestsForAsset(2); got != 1 {
			t.Fatalf("key requests = %d, want 1", got)
		}
	})

	t.Run("500 retries", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "retry.key")
		keyBody := []byte("key")
		assets, bodies := releaseWithChecksumAndKey("retry.key", keyBody)
		server := newTestReleaseServer(t, assets, bodies)
		server.setAssetStatuses(2, http.StatusInternalServerError, http.StatusInternalServerError)
		useTestGitHub(t, server)

		err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(2))
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("error = %v, want HTTP 500", err)
		}
		if got := server.requestsForAsset(2); got != 2 {
			t.Fatalf("key requests = %d, want 2", got)
		}
	})
}

func TestChecksumMergePreservesLocalEntriesAndReleaseWins(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "download.key")
	keyBody := []byte("download")
	localOnlySum := checksumHex([]byte("local only"))
	oldConflictSum := checksumHex([]byte("old conflict"))
	newConflictSum := checksumHex([]byte("new conflict"))
	writeTestChecksum(t, dir, map[string]string{
		"local-only.key": localOnlySum,
		"conflict.key":   oldConflictSum,
	})

	releaseChecksum := []byte(fmt.Sprintf("%s  conflict.key\n%s  download.key\n", newConflictSum, checksumHex(keyBody)))
	server := newTestReleaseServer(t, []releaseAsset{
		{ID: 1, Name: "CHECKSUM"},
		{ID: 2, Name: "download.key"},
	}, map[int64][]byte{
		1: releaseChecksum,
		2: keyBody,
	})
	useTestGitHub(t, server)

	if err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("ensure key: %v", err)
	}
	entries, err := parseChecksumFile(filepath.Join(dir, "CHECKSUM"))
	if err != nil {
		t.Fatalf("parse merged CHECKSUM: %v", err)
	}
	if got := entries["local-only.key"]; got != localOnlySum {
		t.Fatalf("local-only checksum = %q, want %q", got, localOnlySum)
	}
	if got := entries["conflict.key"]; got != newConflictSum {
		t.Fatalf("conflict checksum = %q, want release checksum %q", got, newConflictSum)
	}
}

func TestChecksumMergeRetriesAfterFailure(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "retry-checksum.key")
	keyBody := []byte("key")
	assets, bodies := releaseWithChecksumAndKey("retry-checksum.key", keyBody)
	server := newTestReleaseServer(t, assets, bodies)
	server.setAssetStatuses(1, http.StatusInternalServerError, http.StatusOK)
	useTestGitHub(t, server)

	if err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(1)); err == nil {
		t.Fatalf("first ensure succeeded, want CHECKSUM download failure")
	}
	if err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if got := server.requestsForAsset(1); got != 2 {
		t.Fatalf("CHECKSUM requests = %d, want 2", got)
	}
}

func TestChecksumMergeRunsPerTagAndDir(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	keyBody := []byte("shared")
	assets, bodies := releaseWithChecksumAndKey("shared.key", keyBody)
	server := newTestReleaseServer(t, assets, bodies)
	useTestGitHub(t, server)

	if err := EnsureProvingKeyFromRelease(filepath.Join(dir1, "shared.key"), true, testDownloadConfig(1)); err != nil {
		t.Fatalf("ensure dir1: %v", err)
	}
	if err := EnsureProvingKeyFromRelease(filepath.Join(dir2, "shared.key"), true, testDownloadConfig(1)); err != nil {
		t.Fatalf("ensure dir2: %v", err)
	}
	if got := server.requestsForAsset(1); got != 2 {
		t.Fatalf("CHECKSUM requests = %d, want 2", got)
	}
}

func TestProvingKeysReleaseTagOverride(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "override.key")
	keyBody := []byte("key")
	assets, bodies := releaseWithChecksumAndKey("override.key", keyBody)
	server := newTestReleaseServer(t, assets, bodies)
	useTestGitHub(t, server)
	t.Setenv(provingKeysReleaseTagEnvVar, "custom-tag")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "test-token")

	if err := EnsureProvingKeyFromRelease(keyPath, true, testDownloadConfig(1)); err != nil {
		t.Fatalf("ensure override key: %v", err)
	}
	if !server.sawReleaseTag("custom-tag") {
		t.Fatalf("release tag override was not used")
	}
	if !server.sawAuthorization("Bearer test-token") {
		t.Fatalf("authorization bearer token was not sent")
	}
}
