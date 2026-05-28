package spp

import "testing"

func TestSupportedShapes(t *testing.T) {
	tests := []Shape{
		{NInputs: 2, NOutputs: 2},
		{NInputs: 1, NOutputs: 2},
		{NInputs: 3, NOutputs: 3},
		{NInputs: 5, NOutputs: 3},
		{NInputs: 1, NOutputs: 8},
	}

	for _, shape := range tests {
		if err := shape.Validate(); err != nil {
			t.Fatalf("expected shape %s to be supported: %v", shape, err)
		}
	}
}

func TestUnsupportedShapes(t *testing.T) {
	tests := []Shape{
		{NInputs: 0, NOutputs: 1},
		{NInputs: 1, NOutputs: 0},
		{NInputs: 1, NOutputs: 1},
		{NInputs: 3, NOutputs: 2},
	}

	for _, shape := range tests {
		if err := shape.Validate(); err == nil {
			t.Fatalf("expected shape %s to be rejected", shape)
		}
	}
}

func TestLogicalPublicInputsMatchSpecSet(t *testing.T) {
	expected := []string{
		"nullifiers",
		"output_utxo_hashes",
		"utxo_tree_roots",
		"nullifier_tree_roots",
		"private_tx_hash",
		"external_data_hash",
		"public_sol_amount",
		"public_spl_amount",
		"public_spl_asset_id",
		"ProgramIDHashchain",
		"SolanaPubkeyHash",
		"data_hash",
		"policy_data",
		"solana_pk_hashes",
	}

	if len(LogicalPublicInputNames) != len(expected) {
		t.Fatalf("public input count mismatch: got %d want %d", len(LogicalPublicInputNames), len(expected))
	}
	for i := range expected {
		if LogicalPublicInputNames[i] != expected[i] {
			t.Fatalf("public input %d mismatch: got %q want %q", i, LogicalPublicInputNames[i], expected[i])
		}
	}
}
