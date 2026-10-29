package common

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

func TestProvingKeyDownloadsMatchSharedCatalog(t *testing.T) {
	t.Setenv(provingKeysURLEnvVar, defaultProvingKeysBaseURL)
	data, err := os.ReadFile("../../../../test-vectors/proving_key_catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected ProvingKeysReport
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	report, err := ProvingKeyDownloads()
	if err != nil {
		t.Fatal(err)
	}
	var selected []ProvingKeyStatus
	for _, key := range report.Keys {
		for _, want := range expected.Keys {
			if key.Name == want.Name {
				selected = append(selected, key)
			}
		}
	}
	if !reflect.DeepEqual(selected, expected.Keys) {
		t.Fatalf("catalog differs: %+v", selected)
	}
}

func TestDownloadURLsUseEachManifestPrefixAndReleaseSource(t *testing.T) {
	t.Setenv(provingKeysURLEnvVar, "https://mirror.example/assets/")
	manifest := &lockManifest{Prefix: "proving-keys/new", Keys: map[string]lockEntry{
		"test.key":    {Sha256: "source-sha", Size: 10},
		"release.key": {Sha256: "release-sha", Size: 30, Source: "release", URL: "https://release.example/v1/release.key"},
	}}
	zopro := &provingkeys.ZoproManifest{Prefix: "proving-keys/old", Keys: map[string]provingkeys.ZoproEntry{
		"test.key": {File: "test.zopro", Sha256: "zopro-sha", Size: 20},
	}}
	report := provingKeyDownloads(manifest, zopro)
	want := []ProvingKeyStatus{
		{Name: "release.key", Artifacts: []ProvingKeyArtifact{{Format: "gnark", Sha256: "release-sha", Size: 30, URL: "https://release.example/v1/release.key"}}},
		{Name: "test.key", Artifacts: []ProvingKeyArtifact{
			{Format: "gnark", Sha256: "source-sha", Size: 10, URL: "https://mirror.example/assets/proving-keys/new/test.key"},
			{Format: "zopro", Sha256: "zopro-sha", Size: 20, URL: "https://mirror.example/assets/proving-keys/old/test.zopro"},
		}},
	}
	if !reflect.DeepEqual(report.Keys, want) {
		t.Fatalf("catalog = %+v, want %+v", report.Keys, want)
	}
}
