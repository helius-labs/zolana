package common

import (
	"sort"

	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

// ProvingKeyArtifact describes the exact bytes of one public download.
type ProvingKeyArtifact struct {
	Format string `json:"format"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
	URL    string `json:"url"`
}

// ProvingKeyStatus groups the original gnark key and its published conversions.
// The gnark artifact's digest identifies the key used by proof responses.
type ProvingKeyStatus struct {
	Name      string               `json:"name"`
	Artifacts []ProvingKeyArtifact `json:"artifacts"`
}

type ProvingKeysReport struct {
	Keys []ProvingKeyStatus `json:"keys"`
}

// ProvingKeyDownloads lists only manifest-backed downloads. It does not inspect
// local files, load keys, contact the object store, or describe proof routing.
func ProvingKeyDownloads() (*ProvingKeysReport, error) {
	manifest, err := loadManifest()
	if err != nil {
		return nil, err
	}
	zopro, err := provingkeys.LoadZopro()
	if err != nil {
		return nil, err
	}
	return provingKeyDownloads(manifest, zopro), nil
}

func provingKeyDownloads(manifest *lockManifest, zopro *provingkeys.ZoproManifest) *ProvingKeysReport {
	names := make([]string, 0, len(manifest.Keys))
	for name := range manifest.Keys {
		names = append(names, name)
	}
	sort.Strings(names)
	report := &ProvingKeysReport{Keys: make([]ProvingKeyStatus, 0, len(names))}
	for _, name := range names {
		entry := manifest.Keys[name]
		url := entry.URL
		if url == "" {
			url = objectURL(manifest.Prefix, name)
		}
		artifacts := []ProvingKeyArtifact{{Format: "gnark", Sha256: entry.Sha256, Size: entry.Size, URL: url}}
		if converted, ok := zopro.Keys[name]; ok {
			artifacts = append(artifacts, ProvingKeyArtifact{
				Format: "zopro", Sha256: converted.Sha256, Size: converted.Size,
				URL: objectURL(zopro.Prefix, converted.File),
			})
		}
		report.Keys = append(report.Keys, ProvingKeyStatus{Name: name, Artifacts: artifacts})
	}
	return report
}
