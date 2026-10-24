// Package provingkeys embeds and parses the committed proving-keys lockfile.
// The lockfile pins the sha256 and byte size of every distributable proving
// key; embedding it means the integrity guarantee travels with the binary and
// cannot be swapped out at runtime.
package provingkeys

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sync"
)

// proving-keys.lock pins the sha256 and size of every distributable proving key.
//
//go:embed proving-keys.lock
var embeddedLockfile []byte

// Entry is a single pinned key: its sha256 (lowercase hex) and exact size in
// bytes. Both are checked against the bytes actually written to disk.
type Entry struct {
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Names where a key comes from when the object store does not carry it.
	Source string `json:"source,omitempty"`
	URL    string `json:"-"`
}

// Manifest is the parsed proving-keys.lock: the object-store prefix under the
// base URL plus the pinned keys, keyed by bare filename.
type Manifest struct {
	Prefix string           `json:"prefix"`
	Keys   map[string]Entry `json:"keys"`
}

var (
	// A bare file name, so a key never lands outside the keys directory.
	extensionKeyName = regexp.MustCompile(`^[a-z0-9_]+\.key$`)
	sha256Hex        = regexp.MustCompile(`^[0-9a-f]{64}$`)

	once       sync.Once
	loaded     bool
	extensions [][]byte
	manifest   *Manifest
	loadErr    error
)

// Register runs in an extension package init.
func Register(lockfile []byte) {
	if loaded {
		panic("provingkeys.Register after Load")
	}
	extensions = append(extensions, lockfile)
}

// Load parses the embedded lockfile exactly once and caches the result
// (including a parse error, which then surfaces on every subsequent call).
func Load() (*Manifest, error) {
	once.Do(func() {
		loaded = true
		manifest, loadErr = parse(embeddedLockfile, extensions)
	})
	return manifest, loadErr
}

func parse(embedded []byte, extensions [][]byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(embedded, &m); err != nil {
		return nil, fmt.Errorf("failed to parse embedded proving-keys lockfile: %w", err)
	}
	if len(m.Keys) == 0 {
		return nil, fmt.Errorf("embedded proving-keys lockfile has no keys")
	}
	for _, lockfile := range extensions {
		var extension struct {
			Release string           `json:"release"`
			Keys    map[string]Entry `json:"keys"`
		}
		if err := json.Unmarshal(lockfile, &extension); err != nil {
			return nil, fmt.Errorf("failed to parse extension proving-keys lockfile: %w", err)
		}
		if extension.Release == "" {
			return nil, fmt.Errorf("extension proving-keys lockfile names no release URL")
		}
		for name, entry := range extension.Keys {
			if !extensionKeyName.MatchString(name) || !sha256Hex.MatchString(entry.Sha256) || entry.Size <= 0 {
				return nil, fmt.Errorf("extension key %s has an invalid name, sha256 or size", name)
			}
			if _, pinned := m.Keys[name]; pinned {
				return nil, fmt.Errorf("extension lockfile repins %s", name)
			}
			// The object-store prefix covers the embedded keys alone.
			if entry.Source == "" {
				return nil, fmt.Errorf("extension key %s names no source", name)
			}
			download, err := url.JoinPath(extension.Release, name)
			if err != nil {
				return nil, fmt.Errorf("extension key %s has no valid release URL: %w", name, err)
			}
			entry.URL = download
			m.Keys[name] = entry
		}
	}
	return &m, nil
}
