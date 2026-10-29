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

func TestZoproManifestRejectsWrongSourceAndInvalidArtifacts(t *testing.T) {
	base := &Manifest{Prefix: "proving-keys/new", Keys: map[string]Entry{"test.key": {Sha256: strings.Repeat("a", 64), Size: 10}}}
	for _, field := range []string{"valid", "source", "file", "sha256", "size", "prefix", "unknown"} {
		t.Run(field, func(t *testing.T) {
			entry := ZoproEntry{File: "test.zopro", Sha256: strings.Repeat("b", 64), Size: 20, KeySha256: strings.Repeat("a", 64)}
			manifest := ZoproManifest{Prefix: "proving-keys/old", Keys: map[string]ZoproEntry{}}
			name := "test.key"
			switch field {
			case "source":
				entry.KeySha256 = strings.Repeat("c", 64)
			case "file":
				entry.File = "../test.zopro"
			case "sha256":
				entry.Sha256 = "bad"
			case "size":
				entry.Size = 0
			case "prefix":
				manifest.Prefix = "../old"
			case "unknown":
				name = "unknown.key"
			}
			manifest.Keys[name] = entry
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			_, err = parseZopro(data, base)
			if (err == nil) != (field == "valid") {
				t.Fatalf("parseZopro error = %v", err)
			}
		})
	}
}
