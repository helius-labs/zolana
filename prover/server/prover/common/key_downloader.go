package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// checksumMergeOnce serializes the once-per-release CHECKSUM merge. Preloading N
// keys (see EnsureKeysExist) would otherwise re-download and re-merge the
// identical release CHECKSUM N times, racing on dir/CHECKSUM. A sync.Once per
// release tag (keyed under checksumMergeMu) makes the merge run exactly once per
// process regardless of whether EnsureKeysExist iterates sequentially or
// concurrently. The stored error is memoized so later callers see the same
// outcome without retrying.
var (
	checksumMergeMu   sync.Mutex
	checksumMergeOnce = map[string]*checksumMergeState{}
)

type checksumMergeState struct {
	once sync.Once
	err  error
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
	ProvingKeysReleaseTag       = "transfer-keys-v10"
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

// releaseTag returns the release tag to fetch keys from, honoring the
// PROVING_KEYS_RELEASE_TAG override.
func releaseTag() string {
	if v := strings.TrimSpace(os.Getenv(provingKeysReleaseTagEnvVar)); v != "" {
		return v
	}
	return ProvingKeysReleaseTag
}

// githubToken returns the bearer token used to reach the private proving-keys
// release, honoring the env names the `gh` CLI also reads.
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
		fmt.Fprintf(&b, "%s  %s\n", entries[name], name)
	}

	tempPath := path + ".merge.tmp"
	if err := os.WriteFile(tempPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("failed to write temp CHECKSUM %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp CHECKSUM to %s: %w", path, err)
	}
	return nil
}

// mergeReleaseChecksum downloads the release CHECKSUM to a distinct temp path
// (never dir/CHECKSUM, so the shared local manifest is not clobbered mid-merge),
// parses it, and merges its entries into dir/CHECKSUM: local-only entries (e.g.
// locally generated squads keys) are preserved and release entries override
// same-filename local entries. The merged file is written atomically.
func mergeReleaseChecksum(assets []releaseAsset, dir string) error {
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
	defer os.RemoveAll(stageDir)

	if err := downloadMatchingAssets(assets, "CHECKSUM", stageDir); err != nil {
		return fmt.Errorf("failed to download release CHECKSUM: %w", err)
	}
	releasePath := filepath.Join(stageDir, "CHECKSUM")

	release, err := parseChecksumFile(releasePath)
	if err != nil {
		return fmt.Errorf("failed to read release CHECKSUM: %w", err)
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
// exactly once per release tag for the lifetime of the process, regardless of
// how many keys are being preloaded and whether they are handled sequentially or
// concurrently. mergeReleaseChecksum reuses the already-fetched asset list.
func ensureReleaseChecksum(assets []releaseAsset, dir string) error {
	tag := releaseTag()
	checksumMergeMu.Lock()
	state, ok := checksumMergeOnce[tag]
	if !ok {
		state = &checksumMergeState{}
		checksumMergeOnce[tag] = state
	}
	checksumMergeMu.Unlock()

	state.once.Do(func() {
		state.err = mergeReleaseChecksum(assets, dir)
	})
	return state.err
}

func verifyChecksum(filepath string, expectedChecksum string) (bool, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))
	return actualChecksum == expectedChecksum, nil
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
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", ProvingKeysRepo, tag)
	req, err := githubAPIRequest(http.MethodGet, url, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	resp, err := metadataHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query release %s@%s: %w", ProvingKeysRepo, tag, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		hint := ""
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			hint = " (set GITHUB_TOKEN/GH_TOKEN with read access to the private proving-keys repo)"
		}
		return nil, fmt.Errorf("failed to query release %s@%s: HTTP %d%s: %s", ProvingKeysRepo, tag, resp.StatusCode, hint, strings.TrimSpace(string(body)))
	}
	var release struct {
		Assets []releaseAsset `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode release metadata: %w", err)
	}
	return release.Assets, nil
}

// downloadMatchingAssets downloads every asset in assets whose name matches
// pattern (a filepath.Match glob) into dir via the GitHub REST API. Errors if
// nothing matches. Callers pass a pre-fetched asset list so a single
// listReleaseAssets result can serve several patterns.
func downloadMatchingAssets(assets []releaseAsset, pattern string, dir string) error {
	matched := 0
	for _, asset := range assets {
		ok, err := filepath.Match(pattern, asset.Name)
		if err != nil {
			return fmt.Errorf("invalid asset pattern %q: %w", pattern, err)
		}
		if !ok {
			continue
		}
		if err := downloadAssetByID(asset.ID, filepath.Join(dir, asset.Name)); err != nil {
			return fmt.Errorf("failed to download asset %s: %w", asset.Name, err)
		}
		matched++
	}
	if matched == 0 {
		return fmt.Errorf("no asset matches %q in release %s@%s", pattern, ProvingKeysRepo, releaseTag())
	}
	return nil
}

// downloadReleaseAsset downloads every asset whose name matches pattern (a
// filepath.Match glob) into dir via the GitHub REST API. Errors if nothing
// matches. Replaces the `gh` CLI so downloads work in the distroless image.
func downloadReleaseAsset(pattern string, dir string) error {
	assets, err := listReleaseAssets()
	if err != nil {
		return err
	}
	return downloadMatchingAssets(assets, pattern, dir)
}

// downloadAssetByID streams a release asset (by numeric id) to outputPath,
// retrying with backoff. With Accept: application/octet-stream GitHub redirects
// to signed storage on a different host; the default client follows it and drops
// the bearer token on that hop (the redirect URL is already signed).
func downloadAssetByID(id int64, outputPath string) error {
	assetURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/assets/%d", ProvingKeysRepo, id)
	tempPath := outputPath + ".tmp"
	var lastErr error
	for attempt := 1; attempt <= DefaultMaxRetries; attempt++ {
		if attempt > 1 {
			delay := calculateBackoff(attempt-1, DefaultRetryDelay, DefaultMaxRetryDelay)
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
		client := &http.Client{Timeout: 60 * time.Minute}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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
			resp.Body.Close()
			return fmt.Errorf("failed to create temp file %s: %w", tempPath, err)
		}
		_, copyErr := io.Copy(file, resp.Body)
		resp.Body.Close()
		if closeErr := file.Close(); closeErr != nil && copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			os.Remove(tempPath)
			lastErr = copyErr
			continue
		}
		if err := os.Rename(tempPath, outputPath); err != nil {
			return fmt.Errorf("failed to rename temp file to %s: %w", outputPath, err)
		}
		logging.Logger().Info().
			Str("file", filepath.Base(outputPath)).
			Msg("Release asset downloaded")
		return nil
	}
	return fmt.Errorf("failed to download asset after %d attempts: %w", DefaultMaxRetries, lastErr)
}

// EnsureProvingKeyFromRelease makes a Zolana proving key available at keyPath,
// fetching it (and the release CHECKSUM) from the private GitHub release via the
// REST API with a bearer token (GITHUB_TOKEN / GH_TOKEN). If the file is already
// present and verifies against the local CHECKSUM, no download happens. When
// autoDownload is false, a missing file is an error.
func EnsureProvingKeyFromRelease(keyPath string, autoDownload bool) error {
	filename := filepath.Base(keyPath)
	dir := filepath.Dir(keyPath)

	if localChecksum, ok := readLocalChecksum(dir, filename); ok {
		if _, err := os.Stat(keyPath); err == nil {
			if valid, verr := verifyChecksum(keyPath, localChecksum); verr == nil && valid {
				logging.Logger().Info().
					Str("file", filename).
					Msg("Proving key verified against local CHECKSUM, skipping download")
				return nil
			}
		}
	}

	if !autoDownload {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
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
	if err := ensureReleaseChecksum(assets, dir); err != nil {
		return err
	}

	if err := downloadMatchingAssets(assets, filename, dir); err != nil {
		logging.Logger().Info().
			Err(err).
			Str("file", filename).
			Msg("Exact release asset unavailable; trying split asset parts")
		if partsErr := downloadMatchingAssets(assets, filename+".part-*", dir); partsErr != nil {
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
		os.Remove(keyPath)
		return fmt.Errorf("downloaded file %s checksum mismatch", filename)
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
	defer out.Close()

	for _, part := range parts {
		in, err := os.Open(part)
		if err != nil {
			os.Remove(tempPath)
			return fmt.Errorf("failed to open split asset %s: %w", part, err)
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			os.Remove(tempPath)
			return fmt.Errorf("failed to append split asset %s: %w", part, err)
		}
		if err := in.Close(); err != nil {
			os.Remove(tempPath)
			return fmt.Errorf("failed to close split asset %s: %w", part, err)
		}
	}
	if err := out.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to close assembled key %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to move assembled key to %s: %w", outputPath, err)
	}
	return nil
}

// EnsureTransferKeyFromRelease is kept for call sites and tests that still use
// the old transfer-specific name.
func EnsureTransferKeyFromRelease(keyPath string, autoDownload bool) error {
	return EnsureProvingKeyFromRelease(keyPath, autoDownload)
}

func EnsureKeysExist(keys []string, config *DownloadConfig) error {
	if !config.AutoDownload {
		for _, key := range keys {
			if _, err := os.Stat(key); os.IsNotExist(err) {
				return fmt.Errorf("required key file not found: %s (auto-download disabled)", key)
			}
		}
		return nil
	}

	var missingKeys []string
	for _, key := range keys {
		if _, err := os.Stat(key); os.IsNotExist(err) {
			missingKeys = append(missingKeys, key)
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

			if err := EnsureProvingKeyFromRelease(key, config.AutoDownload); err != nil {
				return fmt.Errorf("failed to download key %s: %w", filepath.Base(key), err)
			}
		}
	}

	return nil
}
