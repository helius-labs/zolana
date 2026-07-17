package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"zolana/prover/logging"
)

// metadataHTTPClient fetches the small release-metadata JSON. Asset downloads
// use their own long-timeout client (see downloadAssetByID); metadata is a tiny
// GET, so a short bounded timeout keeps a stalled connection from hanging the
// whole key-download path forever.
var metadataHTTPClient = &http.Client{Timeout: 30 * time.Second}
var assetHTTPClient = &http.Client{Timeout: 60 * time.Minute}
var githubAPIBaseURL = "https://api.github.com"

// checksumMergeStates serializes the once-per-release-dir CHECKSUM merge. Preloading N
// keys (see EnsureKeysExist) would otherwise re-download and re-merge the
// identical release CHECKSUM N times, racing on dir/CHECKSUM. A state per
// release tag and destination dir (keyed under checksumMergeMu) makes the merge
// run once per process after it succeeds, while transient failures remain
// retryable by later callers.
var (
	checksumMergeMu     sync.Mutex
	checksumMergeStates = map[string]*checksumMergeState{}
)

type checksumMergeState struct {
	mu   sync.Mutex
	done bool
}

const (
	DefaultMaxRetries    = 10
	DefaultRetryDelay    = 5 * time.Second
	DefaultMaxRetryDelay = 5 * time.Minute

	// ProvingKeysRepo and ProvingKeysReleaseTag identify the GitHub release that
	// hosts every Zolana proving key and its CHECKSUM. They must match the
	// repo/tag used by scripts/publish_keys_release.sh. The repo is private, so
	// assets are fetched from the GitHub REST API with a bearer token from
	// GITHUB_TOKEN / GH_TOKEN -- this works in the distroless prover image, which
	// has no `gh` CLI. The tag is overridable via PROVING_KEYS_RELEASE_TAG so key
	// rotations don't require a prover rebuild.
	ProvingKeysRepo             = "helius-labs/zolana"
	ProvingKeysReleaseTag       = "transfer-keys-v12"
	provingKeysReleaseTagEnvVar = "PROVING_KEYS_RELEASE_TAG"
)

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

// releaseTag returns the release tag to fetch keys from, honoring the
// PROVING_KEYS_RELEASE_TAG override.
func releaseTag() string {
	if v := strings.TrimSpace(os.Getenv(provingKeysReleaseTagEnvVar)); v != "" {
		return v
	}
	return ProvingKeysReleaseTag
}

// githubToken returns the bearer token used to reach the private proving-keys
// release, honoring both token env names used locally and in CI.
func githubToken() string {
	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	return ""
}

// readLocalChecksum looks up filename in a CHECKSUM file located in dir (format:
// "checksum  filename" per line). Returns the checksum and true if found.
func readLocalChecksum(dir string, filename string) (string, bool) {
	content, err := os.ReadFile(filepath.Join(dir, "CHECKSUM"))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(content), "\n") {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) >= 2 && parts[1] == filename {
			return parts[0], true
		}
	}
	return "", false
}

// parseChecksumFile reads a CHECKSUM file (format "checksum  filename" per
// line, as written by scripts/generate_checksums.py) into a filename->checksum
// map. A missing file yields an empty map (not an error) so a first-ever
// download can still merge into a fresh CHECKSUM.
func parseChecksumFile(path string) (map[string]string, error) {
	entries := map[string]string{}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(content), "\n") {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) >= 2 {
			entries[parts[1]] = parts[0]
		}
	}
	return entries, nil
}

// writeChecksumFile writes entries to path in the canonical "checksum  filename"
// format (two spaces, sorted by filename to match generate_checksums.py) via a
// temp file + rename so a concurrent reader never sees a partial CHECKSUM.
func writeChecksumFile(path string, entries map[string]string) error {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		if _, err := fmt.Fprintf(&b, "%s  %s\n", entries[name], name); err != nil {
			return fmt.Errorf("failed to format CHECKSUM entry %s: %w", name, err)
		}
	}

	tempPath := path + ".merge.tmp"
	if err := os.WriteFile(tempPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("failed to write temp CHECKSUM %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		removeErr := removeFileIfExists(tempPath)
		return errors.Join(
			fmt.Errorf("failed to rename temp CHECKSUM to %s: %w", path, err),
			wrapCleanupError("failed to remove temp CHECKSUM", tempPath, removeErr),
		)
	}
	return nil
}

// mergeReleaseChecksum downloads the release CHECKSUM to a distinct temp path
// (never dir/CHECKSUM, so the shared local manifest is not clobbered mid-merge),
// parses it, and merges its entries into dir/CHECKSUM: local-only entries (e.g.
// locally generated squads keys) are preserved and release entries override
// same-filename local entries. The merged file is written atomically.
func mergeReleaseChecksum(assets []releaseAsset, dir string, config *DownloadConfig) error {
	localPath := filepath.Join(dir, "CHECKSUM")
	local, err := parseChecksumFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read local CHECKSUM %s: %w", localPath, err)
	}

	// downloadMatchingAssets writes to <passed-dir>/<asset name>, i.e. it would
	// clobber dir/CHECKSUM. Download into a temp subdirectory instead so the
	// shared local CHECKSUM is never overwritten by the raw release manifest --
	// even if the merge below fails partway through.
	stageDir, err := os.MkdirTemp(dir, "checksum-release-")
	if err != nil {
		return fmt.Errorf("failed to create release CHECKSUM staging dir: %w", err)
	}

	if err := downloadMatchingAssets(assets, "CHECKSUM", stageDir, config); err != nil {
		cleanupErr := os.RemoveAll(stageDir)
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("failed to remove release CHECKSUM staging dir %s: %w", stageDir, cleanupErr)
		}
		return errors.Join(
			fmt.Errorf("failed to download release CHECKSUM: %w", err),
			cleanupErr,
		)
	}
	releasePath := filepath.Join(stageDir, "CHECKSUM")

	release, err := parseChecksumFile(releasePath)
	if err != nil {
		cleanupErr := os.RemoveAll(stageDir)
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("failed to remove release CHECKSUM staging dir %s: %w", stageDir, cleanupErr)
		}
		return errors.Join(fmt.Errorf("failed to read release CHECKSUM: %w", err), cleanupErr)
	}
	if err := os.RemoveAll(stageDir); err != nil {
		return fmt.Errorf("failed to remove release CHECKSUM staging dir %s: %w", stageDir, err)
	}

	// Union: start from local, let release entries override same-filename ones.
	merged := make(map[string]string, len(local)+len(release))
	for name, sum := range local {
		merged[name] = sum
	}
	for name, sum := range release {
		merged[name] = sum
	}
	return writeChecksumFile(localPath, merged)
}

// ensureReleaseChecksum fetches and merges the release CHECKSUM into dir/CHECKSUM
// once per release tag and destination dir for the lifetime of the process,
// after a successful merge. mergeReleaseChecksum reuses the already-fetched
// asset list.
func ensureReleaseChecksum(assets []releaseAsset, dir string, config *DownloadConfig) error {
	key := releaseTag() + "\x00" + dir
	checksumMergeMu.Lock()
	state, ok := checksumMergeStates[key]
	if !ok {
		state = &checksumMergeState{}
		checksumMergeStates[key] = state
	}
	checksumMergeMu.Unlock()

	state.mu.Lock()
	if state.done {
		state.mu.Unlock()
		return nil
	}
	if err := mergeReleaseChecksum(assets, dir, config); err != nil {
		state.mu.Unlock()
		return err
	}
	state.done = true
	state.mu.Unlock()
	return nil
}

func verifyChecksum(filePath string, expectedChecksum string) (bool, error) {
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
	actualChecksum := hex.EncodeToString(hash.Sum(nil))
	return actualChecksum == expectedChecksum, nil
}

func removeFileIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func wrapCleanupError(msg string, path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s %s: %w", msg, path, err)
}

func cleanupTempFile(path string, originalErr error) error {
	if removeErr := removeFileIfExists(path); removeErr != nil {
		return errors.Join(originalErr, fmt.Errorf("failed to remove temp file %s: %w", path, removeErr))
	}
	return originalErr
}

func cleanupOpenTempFile(file *os.File, path string, originalErr error) error {
	closeErr := file.Close()
	err := cleanupTempFile(path, originalErr)
	if closeErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to close temp file %s: %w", path, closeErr))
	}
	return err
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

func githubAPIURL(path string) string {
	return strings.TrimRight(githubAPIBaseURL, "/") + path
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

type releaseAsset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// githubAPIRequest builds a GitHub REST API request carrying the bearer token
// (when set) and the standard API headers.
func githubAPIRequest(method, url, accept string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return req, nil
}

// listReleaseAssets fetches the asset list for the configured release tag. The
// proving-keys repo is private, so the request carries a bearer token.
func listReleaseAssets() ([]releaseAsset, error) {
	tag := releaseTag()
	url := githubAPIURL(fmt.Sprintf("/repos/%s/releases/tags/%s", ProvingKeysRepo, tag))
	req, err := githubAPIRequest(http.MethodGet, url, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	resp, err := metadataHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query release %s@%s: %w", ProvingKeysRepo, tag, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr := readResponseSnippet(resp)
		if readErr != nil {
			return nil, closeResponse(resp, fmt.Errorf("failed to read release %s@%s error response: %w", ProvingKeysRepo, tag, readErr))
		}
		hint := ""
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			hint = " (set GITHUB_TOKEN/GH_TOKEN with read access to the private proving-keys repo)"
		}
		err := fmt.Errorf("failed to query release %s@%s: HTTP %d%s: %s", ProvingKeysRepo, tag, resp.StatusCode, hint, body)
		return nil, closeResponse(resp, err)
	}
	var release struct {
		Assets []releaseAsset `json:"assets"`
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(&release)
	closeErr := closeResponse(resp, nil)
	if decodeErr != nil {
		return nil, fmt.Errorf("failed to decode release metadata: %w", errors.Join(decodeErr, closeErr))
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return release.Assets, nil
}

// downloadMatchingAssets downloads every asset in assets whose name matches
// pattern (a filepath.Match glob) into dir via the GitHub REST API. Errors if
// nothing matches. Callers pass a pre-fetched asset list so a single
// listReleaseAssets result can serve several patterns.
func downloadMatchingAssets(assets []releaseAsset, pattern string, dir string, config *DownloadConfig) error {
	matched := 0
	for _, asset := range assets {
		ok, err := filepath.Match(pattern, asset.Name)
		if err != nil {
			return fmt.Errorf("invalid asset pattern %q: %w", pattern, err)
		}
		if !ok {
			continue
		}
		if err := downloadAssetByID(asset.ID, filepath.Join(dir, asset.Name), config); err != nil {
			return fmt.Errorf("failed to download asset %s: %w", asset.Name, err)
		}
		matched++
	}
	if matched == 0 {
		return fmt.Errorf("no asset matches %q in release %s@%s", pattern, ProvingKeysRepo, releaseTag())
	}
	return nil
}

// downloadAssetByID streams a release asset (by numeric id) to outputPath,
// retrying with backoff. With Accept: application/octet-stream GitHub redirects
// to signed storage on a different host; the default client follows it and drops
// the bearer token on that hop (the redirect URL is already signed).
func downloadAssetByID(id int64, outputPath string, config *DownloadConfig) error {
	config = normalizeDownloadConfig(config)
	assetURL := githubAPIURL(fmt.Sprintf("/repos/%s/releases/assets/%d", ProvingKeysRepo, id))
	tempPath := outputPath + ".tmp"
	var lastErr error
	attempts := maxDownloadAttempts(config)
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			delay := calculateBackoff(attempt-1, config.RetryDelay, config.MaxRetryDelay)
			logging.Logger().Warn().
				Err(lastErr).
				Dur("retry_delay", delay).
				Str("file", filepath.Base(outputPath)).
				Msg("Release asset download failed, retrying")
			time.Sleep(delay)
		}
		req, err := githubAPIRequest(http.MethodGet, assetURL, "application/octet-stream")
		if err != nil {
			return err
		}
		resp, err := assetHTTPClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, readErr := readResponseSnippet(resp)
			if readErr != nil {
				lastErr = fmt.Errorf("HTTP %d; failed to read error body: %w", resp.StatusCode, readErr)
			} else {
				lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
			}
			lastErr = closeResponse(resp, lastErr)
			// Permanent client errors (401/403/404, ...) will never succeed on
			// retry -- fail fast instead of burning every retry with backoff.
			// Rate limiting (429) and server errors (5xx) stay retryable.
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return lastErr
			}
			continue
		}
		file, err := os.Create(tempPath)
		if err != nil {
			return closeResponse(resp, fmt.Errorf("failed to create temp file %s: %w", tempPath, err))
		}
		_, copyErr := io.Copy(file, resp.Body)
		copyErr = closeResponse(resp, copyErr)
		if closeErr := file.Close(); closeErr != nil {
			copyErr = errors.Join(copyErr, closeErr)
		}
		if copyErr != nil {
			lastErr = cleanupTempFile(tempPath, copyErr)
			continue
		}
		if err := os.Rename(tempPath, outputPath); err != nil {
			return cleanupTempFile(tempPath, fmt.Errorf("failed to rename temp file to %s: %w", outputPath, err))
		}
		logging.Logger().Info().
			Str("file", filepath.Base(outputPath)).
			Msg("Release asset downloaded")
		return nil
	}
	return fmt.Errorf("failed to download asset after %d attempts: %w", attempts, lastErr)
}

// EnsureProvingKeyFromRelease makes a Zolana proving key available at keyPath,
// fetching it (and the release CHECKSUM) from the private GitHub release via the
// REST API with a bearer token (GITHUB_TOKEN / GH_TOKEN). If the file is already
// present and verifies against the local CHECKSUM, no download happens. When
// autoDownload is false, a missing file is an error.
func EnsureProvingKeyFromRelease(keyPath string, autoDownload bool, config *DownloadConfig) error {
	config = normalizeDownloadConfig(config)
	filename := filepath.Base(keyPath)
	dir := filepath.Dir(keyPath)

	hadLocalChecksum := false
	localChecksumVerified := false
	var localChecksumErr error
	if localChecksum, ok := readLocalChecksum(dir, filename); ok {
		hadLocalChecksum = true
		if _, err := os.Stat(keyPath); err == nil {
			valid, verr := verifyChecksum(keyPath, localChecksum)
			localChecksumErr = verr
			localChecksumVerified = valid && verr == nil
			if localChecksumVerified {
				logging.Logger().Info().
					Str("file", filename).
					Msg("Proving key verified against local CHECKSUM, skipping download")
				return nil
			}
		} else if !os.IsNotExist(err) {
			localChecksumErr = err
		}
	}

	if !autoDownload {
		if _, err := os.Stat(keyPath); err == nil {
			if hadLocalChecksum && !localChecksumVerified {
				if localChecksumErr != nil {
					return fmt.Errorf("key file %s exists but failed checksum verification (auto-download disabled): %w", filename, localChecksumErr)
				}
				return fmt.Errorf("key file %s exists but failed checksum verification (auto-download disabled)", filename)
			}
			return nil
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat key file %s: %w", filename, err)
		}
		return fmt.Errorf("required key file not found: %s (auto-download disabled)", filename)
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	logging.Logger().Info().
		Str("file", filename).
		Str("repo", ProvingKeysRepo).
		Str("tag", releaseTag()).
		Msg("Downloading proving key from GitHub release via REST API")

	// Fetch the asset list once and reuse it for both the CHECKSUM merge and the
	// key/parts download, so preloading N keys does not make ~2N list calls.
	assets, err := listReleaseAssets()
	if err != nil {
		return err
	}

	// Merge the release CHECKSUM into dir/CHECKSUM once per process (across all
	// EnsureProvingKeyFromRelease calls), preserving locally generated entries.
	if err := ensureReleaseChecksum(assets, dir, config); err != nil {
		return err
	}

	if err := downloadMatchingAssets(assets, filename, dir, config); err != nil {
		logging.Logger().Info().
			Err(err).
			Str("file", filename).
			Msg("Exact release asset unavailable; trying split asset parts")
		if partsErr := downloadMatchingAssets(assets, filename+".part-*", dir, config); partsErr != nil {
			return fmt.Errorf("failed to download release asset %s or split parts: exact: %w; parts: %w", filename, err, partsErr)
		}
		if err := assembleReleaseAssetParts(dir, filename, keyPath); err != nil {
			return err
		}
	}

	expectedChecksum, ok := readLocalChecksum(dir, filename)
	if !ok {
		return fmt.Errorf("downloaded CHECKSUM has no entry for %s", filename)
	}
	valid, err := verifyChecksum(keyPath, expectedChecksum)
	if err != nil {
		return fmt.Errorf("failed to verify downloaded file %s: %w", filename, err)
	}
	if !valid {
		return cleanupTempFile(keyPath, fmt.Errorf("downloaded file %s checksum mismatch", filename))
	}

	logging.Logger().Info().
		Str("file", filename).
		Msg("Proving key downloaded and verified successfully")
	return nil
}

func assembleReleaseAssetParts(dir string, filename string, outputPath string) error {
	partPattern := filepath.Join(dir, filename+".part-*")
	parts, err := filepath.Glob(partPattern)
	if err != nil {
		return fmt.Errorf("failed to glob split assets %s: %w", partPattern, err)
	}
	if len(parts) == 0 {
		return fmt.Errorf("no split release asset parts matched %s", partPattern)
	}
	sort.Strings(parts)

	tempPath := outputPath + ".download"
	out, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create assembled key %s: %w", tempPath, err)
	}

	for _, part := range parts {
		in, err := os.Open(part)
		if err != nil {
			return cleanupOpenTempFile(out, tempPath, fmt.Errorf("failed to open split asset %s: %w", part, err))
		}
		_, copyErr := io.Copy(out, in)
		closeErr := in.Close()
		if copyErr != nil || closeErr != nil {
			err := copyErr
			if closeErr != nil {
				err = errors.Join(err, fmt.Errorf("failed to close split asset %s: %w", part, closeErr))
			}
			if copyErr != nil {
				err = fmt.Errorf("failed to append split asset %s: %w", part, err)
			}
			return cleanupOpenTempFile(out, tempPath, err)
		}
	}
	if err := out.Close(); err != nil {
		return cleanupTempFile(tempPath, fmt.Errorf("failed to close assembled key %s: %w", tempPath, err))
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		return cleanupTempFile(tempPath, fmt.Errorf("failed to move assembled key to %s: %w", outputPath, err))
	}
	for _, part := range parts {
		if err := removeFileIfExists(part); err != nil {
			logging.Logger().Warn().
				Err(err).
				Str("file", filepath.Base(part)).
				Msg("Failed to remove split release asset part")
		}
	}
	return nil
}

func EnsureKeysExist(keys []string, config *DownloadConfig) error {
	config = normalizeDownloadConfig(config)
	if !config.AutoDownload {
		for _, key := range keys {
			if err := EnsureProvingKeyFromRelease(key, false, config); err != nil {
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

		for i, key := range missingKeys {
			logging.Logger().Info().
				Int("current", i+1).
				Int("total", len(missingKeys)).
				Str("file", filepath.Base(key)).
				Msg("Downloading missing key")

			if err := EnsureProvingKeyFromRelease(key, config.AutoDownload, config); err != nil {
				return fmt.Errorf("failed to download key %s: %w", filepath.Base(key), err)
			}
		}
	}

	return nil
}
