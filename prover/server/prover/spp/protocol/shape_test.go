package protocol

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
		{NInputs: 0, NOutputs: 2},
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

func TestPublicInputNamesMatchSpecSet(t *testing.T) {
	expected := []string{
		"nullifiers",
		"output_utxo_hashes",
		"utxo_tree_roots",
		"nullifier_tree_roots",
		"private_tx_hash",
		"p256_message_hash",
		"external_data_hash",
		"public_sol_amount",
		"public_spl_amount",
		"public_spl_asset_pubkey",
		"program_id_hashchain",
		"solana_pubkey_hash",
		"data_hash",
		"zone_data_hash",
		"solana_pk_hashes",
	}

	names := PublicInputNames()
	if len(names) != len(expected) {
		t.Fatalf("public input count mismatch: got %d want %d", len(names), len(expected))
	}
	for i := range expected {
		if names[i] != expected[i] {
			t.Fatalf("public input %d mismatch: got %q want %q", i, names[i], expected[i])
		}
	}

	names[0] = "mutated"
	if PublicInputNames()[0] != expected[0] {
		t.Fatal("public input names should not expose mutable package state")
	}
}
