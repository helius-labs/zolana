package common

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/helius-labs/zolana/prover/server/logging"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// assetHTTPClient fetches proving-key objects. Keys are multi-GB, so the client
// uses a long timeout; the objects are served publicly through CloudFront, so no
// auth header is attached.
var assetHTTPClient = &http.Client{Timeout: 60 * time.Minute}

const (
	DefaultMaxRetries    = 10
	DefaultRetryDelay    = 5 * time.Second
	DefaultMaxRetryDelay = 5 * time.Minute

	// defaultProvingKeysBaseURL is the CloudFront distribution in front of the
	// S3 bucket that hosts every Zolana proving key. Override it with
	// ZOLANA_PROVING_KEYS_URL (e.g. to point at a mirror or a local server).
	defaultProvingKeysBaseURL = "https://d3gbdb0egjwcw9.cloudfront.net"
	provingKeysURLEnvVar      = "ZOLANA_PROVING_KEYS_URL"
)

// lockManifest and lockEntry alias the types owned by the provingkeys package so
// the download logic here reads naturally while the embedded lockfile stays in
// that dedicated leaf package.
type lockManifest = provingkeys.Manifest
type lockEntry = provingkeys.Entry

// manifestForTest, when non-nil, is returned by loadManifest instead of the
// embedded lockfile. It exists purely so tests can exercise the lookup logic
// with a small synthetic manifest; production code never sets it.
var manifestForTest *lockManifest

// loadManifest returns the pinned proving-key manifest: the embedded lockfile
// parsed by the provingkeys package (cached there), or the test override.
func loadManifest() (*lockManifest, error) {
	if manifestForTest != nil {
		return manifestForTest, nil
	}
	return provingkeys.Load()
}

// baseURL returns the object-store base URL, honoring the ZOLANA_PROVING_KEYS_URL
// override, with any trailing slash trimmed.
func baseURL() string {
	if v := strings.TrimSpace(os.Getenv(provingKeysURLEnvVar)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultProvingKeysBaseURL
}

// objectURL builds the download URL for a key: <baseURL>/<prefix>/<filename>.
func objectURL(prefix string, filename string) string {
	base := baseURL()
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return base + "/" + filename
	}
	return base + "/" + prefix + "/" + filename
}

type DownloadConfig struct {
	MaxRetries    int
	RetryDelay    time.Duration
	MaxRetryDelay time.Duration
	AutoDownload  bool
}

func DefaultDownloadConfig() *DownloadConfig {
	return &DownloadConfig{
		MaxRetries:    DefaultMaxRetries,
		RetryDelay:    DefaultRetryDelay,
		MaxRetryDelay: DefaultMaxRetryDelay,
		AutoDownload:  true,
	}
}

func normalizeDownloadConfig(config *DownloadConfig) *DownloadConfig {
	if config == nil {
		return DefaultDownloadConfig()
	}
	return config
}

func maxDownloadAttempts(config *DownloadConfig) int {
	if config.MaxRetries < 1 {
		return 1
	}
	return config.MaxRetries
}

func calculateBackoff(attempt int, initialDelay, maxDelay time.Duration) time.Duration {
	delay := initialDelay * time.Duration(1<<uint(attempt-1))
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

// verifySha256 streams filePath through sha256 and reports whether it equals
// expectedHex (case-insensitive; both sides are lowercase hex in practice).
func verifySha256(filePath string, expectedHex string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return false, copyErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	return strings.EqualFold(actual, expectedHex), nil
}

func removeFileIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func cleanupTempFile(path string, originalErr error) error {
	if removeErr := removeFileIfExists(path); removeErr != nil {
		return errors.Join(originalErr, fmt.Errorf("failed to remove temp file %s: %w", path, removeErr))
	}
	return originalErr
}

func readResponseSnippet(resp *http.Response) (string, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func closeResponse(resp *http.Response, originalErr error) error {
	if closeErr := resp.Body.Close(); closeErr != nil {
		return errors.Join(originalErr, fmt.Errorf("failed to close response body for %s: %w", resp.Request.URL.String(), closeErr))
	}
	return originalErr
}

// downloadChunkSize is the byte range fetched per request. CloudFront refuses a
// single response larger than 50 GB, which the batch address-append key
// exceeds, so every key is fetched as ranges well under that cap.
var downloadChunkSize int64 = 1 << 30

// downloadAndVerify fetches url into keyPath, retrying with exponential backoff.
// The object is fetched in byte ranges and appended to keyPath+".tmp"; a retry
// resumes after the bytes already there instead of starting over. The byte count
// and sha256 of the whole temp file are checked against entry before it is
// atomically renamed into place, and a failed check discards it. A permanent
// HTTP error (4xx other than 429) fails fast without exhausting the retry
// budget.
func downloadAndVerify(url string, keyPath string, entry lockEntry, config *DownloadConfig) error {
	config = normalizeDownloadConfig(config)
	tempPath := keyPath + ".tmp"

	var lastErr error
	attempts := maxDownloadAttempts(config)
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			delay := calculateBackoff(attempt-1, config.RetryDelay, config.MaxRetryDelay)
			logging.Logger().Warn().
				Err(lastErr).
				Dur("retry_delay", delay).
				Str("file", filepath.Base(keyPath)).
				Msg("Proving key download failed, retrying")
			time.Sleep(delay)
		}

		permanent, err := downloadAttempt(url, keyPath, tempPath, entry)
		if err == nil {
			logging.Logger().Info().
				Str("file", filepath.Base(keyPath)).
				Msg("Proving key downloaded")
			return nil
		}
		lastErr = err
		if permanent {
			return err
		}
	}
	return fmt.Errorf("failed to download %s after %d attempts: %w", filepath.Base(keyPath), attempts, lastErr)
}

// downloadAttempt fetches the rest of the object into tempPath, then verifies
// and renames it. It returns permanent=true for errors that will never succeed
// on retry (a malformed URL or a permanent 4xx other than 429). A transport or
// server error keeps the temp file so the next attempt resumes; a verification
// failure removes it, so a bad download is never renamed into place.
func downloadAttempt(url string, keyPath string, tempPath string, entry lockEntry) (permanent bool, err error) {
	file, err := os.OpenFile(tempPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return false, fmt.Errorf("failed to open temp file %s: %w", tempPath, err)
	}
	hash := sha256.New()
	// Bytes kept from an earlier attempt are hashed again rather than trusted.
	offset, err := io.Copy(hash, file)
	if err == nil && offset > entry.Size {
		err = fmt.Errorf("temp file %s is larger than the key", tempPath)
	}
	if err != nil {
		closeErr := file.Close()
		return false, cleanupTempFile(tempPath, errors.Join(err, closeErr))
	}

	for offset < entry.Size {
		end := min(offset+downloadChunkSize, entry.Size) - 1
		var written int64
		var full bool
		permanent, written, full, err = fetchRange(url, file, hash, offset, end)
		if err != nil {
			closeErr := file.Close()
			return permanent, errors.Join(err, closeErr)
		}
		if full {
			// The server ignored the range and sent the whole object, which
			// fetchRange wrote over the file from its start.
			offset = written
			break
		}
		offset += written
	}
	if err := file.Close(); err != nil {
		return false, cleanupTempFile(tempPath, fmt.Errorf("failed to close temp file %s: %w", tempPath, err))
	}

	if offset != entry.Size {
		return false, cleanupTempFile(tempPath, fmt.Errorf(
			"downloaded %s size mismatch: got %d bytes, want %d", filepath.Base(keyPath), offset, entry.Size))
	}

	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, entry.Sha256) {
		return false, cleanupTempFile(tempPath, fmt.Errorf(
			"downloaded %s sha256 mismatch: got %s, want %s", filepath.Base(keyPath), actual, entry.Sha256))
	}

	if err := os.Rename(tempPath, keyPath); err != nil {
		return false, cleanupTempFile(tempPath, fmt.Errorf("failed to rename temp file to %s: %w", keyPath, err))
	}
	return false, nil
}

// fetchRange GETs bytes start..end (inclusive) of url and appends them to file
// and digest. A 206 must carry exactly that range. A 200 means the server
// ignored the range: the file and digest are reset and the whole body is written instead,
// reported as full. It returns the number of bytes written.
func fetchRange(url string, file *os.File, digest hash.Hash, start int64, end int64) (permanent bool, written int64, full bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return true, 0, false, fmt.Errorf("failed to build request for %s: %w", url, err)
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	resp, err := assetHTTPClient.Do(req)
	if err != nil {
		return false, 0, false, err
	}

	switch resp.StatusCode {
	case http.StatusPartialContent:
		want := fmt.Sprintf("bytes %d-%d/", start, end)
		if got := resp.Header.Get("Content-Range"); !strings.HasPrefix(got, want) {
			return false, 0, false, closeResponse(resp, fmt.Errorf(
				"range response for %s has Content-Range %q, want %q", url, got, want+"*"))
		}
		written, err = io.Copy(io.MultiWriter(file, digest), io.LimitReader(resp.Body, end-start+1))
		err = closeResponse(resp, err)
		if err == nil && written != end-start+1 {
			err = fmt.Errorf("range %d-%d of %s ended after %d bytes", start, end, url, written)
		}
		return false, written, false, err
	case http.StatusOK:
		if err := file.Truncate(0); err != nil {
			return false, 0, false, closeResponse(resp, err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return false, 0, false, closeResponse(resp, err)
		}
		digest.Reset()
		written, err = io.Copy(io.MultiWriter(file, digest), resp.Body)
		return false, written, true, closeResponse(resp, err)
	default:
		body, readErr := readResponseSnippet(resp)
		var httpErr error
		if readErr != nil {
			httpErr = fmt.Errorf("HTTP %d; failed to read error body: %w", resp.StatusCode, readErr)
		} else {
			httpErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
		}
		httpErr = closeResponse(resp, httpErr)
		// Permanent client errors (401/403/404, ...) never succeed on retry.
		// Rate limiting (429) and server errors (5xx) stay retryable.
		perm := resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests
		return perm, 0, false, httpErr
	}
}

// EnsureProvingKey makes the proving key at keyPath available and verified
// against the embedded lockfile. Keys pinned in the lockfile are downloaded from
// the object store when missing or when the on-disk copy fails its pinned
// sha256; keys not in the lockfile are never downloaded (they must already exist
// locally, e.g. a locally generated key). When autoDownload is false, a missing
// or mismatched pinned key is an error and no file is removed.
func EnsureProvingKey(keyPath string, autoDownload bool, config *DownloadConfig) error {
	config = normalizeDownloadConfig(config)
	filename := filepath.Base(keyPath)

	manifest, err := loadManifest()
	if err != nil {
		return err
	}

	_, statErr := os.Stat(keyPath)
	fileExists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("failed to stat key file %s: %w", filename, statErr)
	}

	entry, inManifest := manifest.Keys[filename]
	if !inManifest {
		if fileExists {
			return nil
		}
		return fmt.Errorf("key %s is not in the proving-keys lockfile and cannot be downloaded", filename)
	}

	if fileExists {
		match, verr := verifySha256(keyPath, entry.Sha256)
		if verr != nil {
			return fmt.Errorf("failed to verify key file %s against lockfile: %w", filename, verr)
		}
		if match {
			logging.Logger().Info().
				Str("file", filename).
				Msg("Proving key verified against lockfile, skipping download")
			return nil
		}
	}

	if entry.Source != "" {
		return fmt.Errorf(
			"key %s is a %s asset and is not on the object store, run just ensure-custom-ring-live-keys",
			filename,
			entry.Source,
		)
	}

	if !autoDownload {
		if fileExists {
			return fmt.Errorf("key file %s exists but does not match the lockfile checksum (auto-download disabled)", filename)
		}
		return fmt.Errorf("required key file not found: %s (auto-download disabled)", filename)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	url := objectURL(manifest.Prefix, filename)
	logging.Logger().Info().
		Str("file", filename).
		Str("url", url).
		Msg("Downloading proving key from object store")

	if err := downloadAndVerify(url, keyPath, entry, config); err != nil {
		return err
	}

	logging.Logger().Info().
		Str("file", filename).
		Msg("Proving key downloaded and verified successfully")
	return nil
}

func EnsureKeysExist(keys []string, config *DownloadConfig) error {
	config = normalizeDownloadConfig(config)
	if !config.AutoDownload {
		for _, key := range keys {
			if err := EnsureProvingKey(key, false, config); err != nil {
				return err
			}
		}
		return nil
	}

	var missingKeys []string
	for _, key := range keys {
		if _, err := os.Stat(key); err != nil {
			if os.IsNotExist(err) {
				missingKeys = append(missingKeys, key)
				continue
			}
			return fmt.Errorf("failed to stat key file %s: %w", key, err)
		}
	}

	if len(missingKeys) > 0 {
		logging.Logger().Info().
			Int("missing_count", len(missingKeys)).
			Int("total_count", len(keys)).
			Msg("Found missing key files, will download")
	}

	// EnsureProvingKey skips keys that are already present and verify against the
	// lockfile, so looping over every key both fills gaps and re-verifies the
	// on-disk copies against their pinned checksums.
	for i, key := range keys {
		logging.Logger().Info().
			Int("current", i+1).
			Int("total", len(keys)).
			Str("file", filepath.Base(key)).
			Msg("Ensuring proving key")

		if err := EnsureProvingKey(key, config.AutoDownload, config); err != nil {
			return fmt.Errorf("failed to ensure key %s: %w", filepath.Base(key), err)
		}
	}

	return nil
}
