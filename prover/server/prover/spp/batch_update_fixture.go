//go:build spp_e2e_fixtures

package spp

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"light/light-prover/prover/common"
	v2 "light/light-prover/prover/v2"
)

const (
	// The on-chain nullifier tree is a Light AddressV2 tree at height 40. Test
	// trees use batch size 10 (production uses 250; both circuits ship in
	// light-protocol). The first forester batch after init starts at tree
	// next_index 1 (the init element occupies index 0).
	batchUpdateTreeHeight = 40
	batchUpdateBatchSize  = 10
	batchUpdateStartIndex = 1
)

// BatchUpdateFixture is the input + baked Light address-append proof for the
// forester batch-update e2e: the litesvm test inserts Values into a fresh tree
// (in this order), submits Proof via batch_update_address_tree, and asserts the
// nullifier root_history advances to NewRoot.
type BatchUpdateFixture struct {
	Height  uint32        `json:"height"`
	Values  []string      `json:"values"`
	OldRoot string        `json:"old_root"`
	NewRoot string        `json:"new_root"`
	Proof   *common.Proof `json:"proof"`
}

// WriteBatchUpdateFixture builds an address-append proof for a deterministic
// batch of 248-bit values using the committed Light proving key and writes the
// fixture JSON. provingKeyPath is the path to batch_address-append_40_10.key.
func WriteBatchUpdateFixture(provingKeyPath string, outputPath string) error {
	fixture, err := buildBatchUpdateFixture(provingKeyPath)
	if err != nil {
		return err
	}
	bytes, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, bytes, 0o644)
}

func buildBatchUpdateFixture(provingKeyPath string) (*BatchUpdateFixture, error) {
	values := make([]*big.Int, batchUpdateBatchSize)
	for i := range values {
		// Deterministic, distinct, increasing values inside the tree's
		// (0, 2^248-1) domain. The Rust e2e inserts these in the same order.
		values[i] = new(big.Int).Lsh(big.NewInt(int64(i)+1), 200)
	}

	params, err := v2.BuildAddressAppendParamsFromValues(batchUpdateTreeHeight, values, batchUpdateStartIndex)
	if err != nil {
		return nil, err
	}
	// The committed key file is a full BatchProofSystem dump (pk+vk+cs behind a
	// height/batch header); ReadSystemFromFile dispatches on the "address-append"
	// name and reads it raw, so the proof is built with the SAME setup the
	// on-chain verifying key came from.
	sys, err := common.ReadSystemFromFile(provingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read address-append proving system %s: %w", provingKeyPath, err)
	}
	bps, ok := sys.(*common.BatchProofSystem)
	if !ok || bps.CircuitType != common.BatchAddressAppendCircuitType {
		return nil, fmt.Errorf("expected an address-append BatchProofSystem at %s", provingKeyPath)
	}
	proof, err := v2.ProveBatchAddressAppend(bps, params)
	if err != nil {
		return nil, fmt.Errorf("prove address-append: %w", err)
	}

	valuesHex := make([]string, len(values))
	for i, v := range values {
		valuesHex[i] = fieldHex(v)
	}
	return &BatchUpdateFixture{
		Height:  batchUpdateTreeHeight,
		Values:  valuesHex,
		OldRoot: fieldHex(params.OldRoot),
		NewRoot: fieldHex(params.NewRoot),
		Proof:   proof,
	}, nil
}
