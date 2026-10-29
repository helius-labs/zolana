package provingkeys

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestZoproManifestPinsCurrentSourceKeys(t *testing.T) {
	manifest, err := LoadZopro()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Keys) != 41 {
		t.Fatalf("zopro keys = %d, want 41", len(manifest.Keys))
	}
}

func TestZoproManifestRejectsWrongSource(t *testing.T) {
	base := &Manifest{Keys: map[string]Entry{"test.key": {Sha256: strings.Repeat("a", 64)}}}
	for _, name := range []string{"test.key", "unknown.key"} {
		manifest := ZoproManifest{Keys: map[string]ZoproEntry{name: {KeySha256: strings.Repeat("b", 64)}}}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseZopro(data, base); err == nil {
			t.Fatalf("accepted wrong source for %s", name)
		}
	}
}
