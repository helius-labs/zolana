// Package provingkeys embeds and parses the committed proving-keys lockfile.
// The lockfile pins the sha256 and byte size of every distributable proving
// key; embedding it means the integrity guarantee travels with the binary and
// cannot be swapped out at runtime.
package provingkeys

import (
	_ "embed"
	"encoding/json"
	"fmt"
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
}

// Manifest is the parsed proving-keys.lock: the object-store prefix under the
// base URL plus the pinned keys, keyed by bare filename.
type Manifest struct {
	Prefix string           `json:"prefix"`
	Keys   map[string]Entry `json:"keys"`
}

var (
	once     sync.Once
	manifest *Manifest
	loadErr  error
)

// Load parses the embedded lockfile exactly once and caches the result
// (including a parse error, which then surfaces on every subsequent call).
func Load() (*Manifest, error) {
	once.Do(func() {
		var m Manifest
		if err := json.Unmarshal(embeddedLockfile, &m); err != nil {
			loadErr = fmt.Errorf("failed to parse embedded proving-keys lockfile: %w", err)
			return
		}
		if len(m.Keys) == 0 {
			loadErr = fmt.Errorf("embedded proving-keys lockfile has no keys")
			return
		}
		manifest = &m
	})
	return manifest, loadErr
}
