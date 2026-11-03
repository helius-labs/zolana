package provingkeys

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRuntimeCoversEveryZoproKey(t *testing.T) {
	runtime, err := Runtime()
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Abi           string                     `json:"abi"`
		VerifyingKeys map[string]json.RawMessage `json:"verifyingKeys"`
	}
	if err := json.Unmarshal(runtime, &metadata); err != nil {
		t.Fatal(err)
	}
	zopro, err := LoadZopro()
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Abi == "" || len(metadata.VerifyingKeys) != len(zopro.Keys) {
		t.Fatalf("runtime keys = %d, zopro keys = %d", len(metadata.VerifyingKeys), len(zopro.Keys))
	}
	for name := range zopro.Keys {
		if _, ok := metadata.VerifyingKeys[name]; !ok {
			t.Fatalf("no runtime verifying key for %s", name)
		}
	}
}

func TestRuntimeRejectsUnpinnedVerifyingKeys(t *testing.T) {
	base := &Manifest{Keys: map[string]Entry{"test.key": {Sha256: strings.Repeat("a", 64)}}}
	for _, data := range []string{
		`{"verifyingKeys":{"test.key":{"provingKeySha256":"` + strings.Repeat("b", 64) + `"}}}`,
		`{"verifyingKeys":{"other.key":{"provingKeySha256":"` + strings.Repeat("a", 64) + `"}}}`,
		`{"verifyingKeys":{}}`,
		`{`,
	} {
		if _, err := parseRuntime([]byte(data), base); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
	if _, err := parseRuntime([]byte(`{"verifyingKeys":{"test.key":{"provingKeySha256":"`+strings.Repeat("a", 64)+`"}}}`), base); err != nil {
		t.Fatal(err)
	}
}
