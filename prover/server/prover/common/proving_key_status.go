package common

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ProvingKeyStatus is one key in the GET /proving-keys response.
type ProvingKeyStatus struct {
	// Name is the key file name, as in proving-keys.lock.
	Name string `json:"name"`
	// ExpectedSha256 is the sha256 proving-keys.lock pins, nil for a key the
	// lockfile does not know. EnsureProvingKey refuses to load any other file
	// under a pinned name, so for a key that is not loaded yet this is the
	// digest the server will prove with.
	ExpectedSha256 *string `json:"expectedSha256"`
	// LoadedSha256 is the sha256 of the bytes actually read, nil until the
	// key is loaded.
	LoadedSha256 *string `json:"loadedSha256"`
	// Available reports whether a proof for this key can be served: it is
	// loaded, on disk, or pinned on the object store with auto-download on.
	// On-disk files are not re-hashed here.
	Available bool `json:"available"`
}

// ProvingKeysReport is the GET /proving-keys response.
type ProvingKeysReport struct {
	// Prefix is the lockfile's version-hashed object-store prefix, i.e. the
	// proving-key version this server pins.
	Prefix string             `json:"prefix"`
	Keys   []ProvingKeyStatus `json:"keys"`
}

// ProvingKeysReport lists every lockfile key plus any other key file that is
// on disk or loaded, sorted by name. It never hashes a file: loaded digests
// were computed while the keys were read.
func (m *LazyKeyManager) ProvingKeysReport() (*ProvingKeysReport, error) {
	manifest, err := loadManifest()
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	loaded := make(map[string][32]byte, len(m.loadedDigests))
	for name, digest := range m.loadedDigests {
		loaded[name] = digest
	}
	m.mu.RUnlock()

	names := make(map[string]struct{}, len(manifest.Keys))
	for name := range manifest.Keys {
		names[name] = struct{}{}
	}
	for name := range loaded {
		names[name] = struct{}{}
	}
	if entries, err := os.ReadDir(m.keysDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".key") {
				names[entry.Name()] = struct{}{}
			}
		}
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	report := &ProvingKeysReport{Prefix: manifest.Prefix, Keys: make([]ProvingKeyStatus, 0, len(sorted))}
	for _, name := range sorted {
		status := ProvingKeyStatus{Name: name}
		entry, pinned := manifest.Keys[name]
		if pinned {
			expected := entry.Sha256
			status.ExpectedSha256 = &expected
		}
		if digest, ok := loaded[name]; ok {
			loadedHex := hex.EncodeToString(digest[:])
			status.LoadedSha256 = &loadedHex
		}
		_, statErr := os.Stat(filepath.Join(m.keysDir, name))
		// A key with a Source (a release asset) is never auto-downloaded.
		downloadable := pinned && entry.Source == "" && m.downloadConfig.AutoDownload
		status.Available = status.LoadedSha256 != nil || statErr == nil || downloadable
		report.Keys = append(report.Keys, status)
	}
	return report, nil
}
