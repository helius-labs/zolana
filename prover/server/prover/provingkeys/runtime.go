package provingkeys

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

// The verifying keys of the confidential signer and merge circuits, written by
// `cargo run -q -p xtask -- runtime-proving-keys` from the protocol crates. Embedding them
// puts them under the enclave measurement, so an attested prover vouches for
// them; clients take a runtime key set only from an encrypted answer.
//
//go:embed runtime-keys.json
var embeddedRuntimeKeys []byte

var loadRuntime = sync.OnceValues(func() (json.RawMessage, error) {
	keys, err := Load()
	if err != nil {
		return nil, err
	}
	return parseRuntime(embeddedRuntimeKeys, keys)
})

// Runtime returns the `runtime` block of the `/proving-keys` catalog.
func Runtime() (json.RawMessage, error) {
	return loadRuntime()
}

// parseRuntime checks that every verifying key belongs to a pinned proving key.
func parseRuntime(data []byte, keys *Manifest) (json.RawMessage, error) {
	var metadata struct {
		VerifyingKeys map[string]struct {
			Sha256 string `json:"provingKeySha256"`
		} `json:"verifyingKeys"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("invalid runtime key metadata: %w", err)
	}
	if len(metadata.VerifyingKeys) == 0 {
		return nil, fmt.Errorf("runtime key metadata lists no verifying keys")
	}
	for name, key := range metadata.VerifyingKeys {
		entry, ok := keys.Keys[name]
		if !ok || entry.Sha256 != key.Sha256 {
			return nil, fmt.Errorf("runtime verifying key %s does not match its pinned proving key", name)
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}
