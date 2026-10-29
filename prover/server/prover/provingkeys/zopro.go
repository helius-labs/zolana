package provingkeys

import (
	_ "embed"
	"encoding/json"
	"fmt"
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

var loadZopro = sync.OnceValues(func() (*ZoproManifest, error) {
	keys, err := Load()
	if err != nil {
		return nil, err
	}
	return parseZopro(embeddedZoproLockfile, keys)
})

func LoadZopro() (*ZoproManifest, error) {
	return loadZopro()
}

func parseZopro(data []byte, keys *Manifest) (*ZoproManifest, error) {
	var manifest ZoproManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid zopro lockfile: %w", err)
	}
	for name, entry := range manifest.Keys {
		key, ok := keys.Keys[name]
		if !ok || entry.KeySha256 != key.Sha256 {
			return nil, fmt.Errorf("zopro artifact %s does not match its pinned gnark key", name)
		}
	}
	return &manifest, nil
}
