package common

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"zolana/prover/logging"
	"zolana/prover/prover/provingkeys"
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

// downloadAndVerify fetches url into keyPath, retrying with exponential backoff.
// The response body is streamed to keyPath+".tmp" while its sha256 is computed in
// the same pass; the byte count and hash are checked against entry before the
// temp file is atomically renamed into place. A permanent HTTP error (4xx other
// than 429) fails fast without exhausting the retry budget.
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

// downloadAttempt performs a single GET+verify+rename. It returns permanent=true
// for errors that will never succeed on retry (a malformed URL or a permanent 4xx
// other than 429). On any verification failure the temp file is removed so a bad
// download is never renamed into place.
func downloadAttempt(url string, keyPath string, tempPath string, entry lockEntry) (permanent bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return true, fmt.Errorf("failed to build request for %s: %w", url, err)
	}

	resp, err := assetHTTPClient.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
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
		return perm, httpErr
	}

	file, err := os.Create(tempPath)
	if err != nil {
		return false, closeResponse(resp, fmt.Errorf("failed to create temp file %s: %w", tempPath, err))
	}

	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), resp.Body)
	copyErr = closeResponse(resp, copyErr)
	if closeErr := file.Close(); closeErr != nil {
		copyErr = errors.Join(copyErr, fmt.Errorf("failed to close temp file %s: %w", tempPath, closeErr))
	}
	if copyErr != nil {
		return false, cleanupTempFile(tempPath, copyErr)
	}

	if written != entry.Size {
		return false, cleanupTempFile(tempPath, fmt.Errorf(
			"downloaded %s size mismatch: got %d bytes, want %d", filepath.Base(keyPath), written, entry.Size))
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
