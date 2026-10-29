package provingkeys

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// The published artifact manifest from zolana-mobile-sdk. Keep its own prefix:
// unchanged source keys do not require republishing their converted artifacts.
//
//go:embed zopro-keys.lock
var embeddedZoproLockfile []byte

type ZoproEntry struct {
	File      string `json:"file"`
	Sha256    string `json:"sha256"`
	Size      int64  `json:"size"`
	KeySha256 string `json:"key_sha256"`
}

type ZoproManifest struct {
	Prefix string                `json:"prefix"`
	Keys   map[string]ZoproEntry `json:"keys"`
}

var (
	zoproOnce     sync.Once
	zoproManifest *ZoproManifest
	zoproErr      error
	zoproPrefix   = regexp.MustCompile(`^proving-keys/[a-zA-Z0-9_-]+$`)
)

func LoadZopro() (*ZoproManifest, error) {
	zoproOnce.Do(func() {
		keys, err := Load()
		if err != nil {
			zoproErr = err
			return
		}
		zoproManifest, zoproErr = parseZopro(embeddedZoproLockfile, keys)
	})
	return zoproManifest, zoproErr
}

func parseZopro(data []byte, keys *Manifest) (*ZoproManifest, error) {
	var manifest ZoproManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid zopro lockfile: %w", err)
	}
	if !zoproPrefix.MatchString(manifest.Prefix) || manifest.Keys == nil {
		return nil, fmt.Errorf("invalid zopro manifest prefix or keys")
	}
	for name, entry := range manifest.Keys {
		key, ok := keys.Keys[name]
		if !ok || entry.KeySha256 != key.Sha256 {
			return nil, fmt.Errorf("zopro artifact %s does not match its pinned gnark key", name)
		}
		if entry.File != strings.TrimSuffix(name, ".key")+".zopro" || !sha256Hex.MatchString(entry.Sha256) || entry.Size <= 0 {
			return nil, fmt.Errorf("invalid zopro artifact %s", name)
		}
	}
	return &manifest, nil
}
