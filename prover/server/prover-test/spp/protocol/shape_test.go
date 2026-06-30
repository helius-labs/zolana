package protocol

import "testing"

func TestSupportedShapes(t *testing.T) {
	tests := []Shape{
		{NInputs: 1, NOutputs: 1},
		{NInputs: 1, NOutputs: 2},
		{NInputs: 2, NOutputs: 2},
		{NInputs: 2, NOutputs: 3},
		{NInputs: 3, NOutputs: 3},
		{NInputs: 4, NOutputs: 3},
		{NInputs: 4, NOutputs: 4},
		{NInputs: 5, NOutputs: 3},
		{NInputs: 5, NOutputs: 4},
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
		{NInputs: 3, NOutputs: 2},
		{NInputs: 2, NOutputs: 4},
		{NInputs: 6, NOutputs: 3},
	}

	for _, shape := range tests {
		if err := shape.Validate(); err == nil {
			t.Fatalf("expected shape %s to be rejected", shape)
		}
	}
}

// TestCanonicalShapeMatchesOnChainSelection mirrors canonical_shape_matches_
// supported_vkeys in transact/proof.rs: both sides must map real input/output
// counts to the same smallest-fit shape, or locally valid proofs cannot verify.
func TestCanonicalShapeMatchesOnChainSelection(t *testing.T) {
	cases := []struct {
		nInputs, nOutputs int
		want              Shape
	}{
		// Exact arities map to themselves.
		{1, 1, Shape{NInputs: 1, NOutputs: 1}},
		{2, 2, Shape{NInputs: 2, NOutputs: 2}},
		{1, 2, Shape{NInputs: 1, NOutputs: 2}},
		{3, 3, Shape{NInputs: 3, NOutputs: 3}},
		{4, 3, Shape{NInputs: 4, NOutputs: 3}},
		{4, 4, Shape{NInputs: 4, NOutputs: 4}},
		{5, 3, Shape{NInputs: 5, NOutputs: 3}},
		{5, 4, Shape{NInputs: 5, NOutputs: 4}},
		{1, 8, Shape{NInputs: 1, NOutputs: 8}},
		// Smaller arities map to the smallest shape with capacity; the unused
		// slots are dummy-padded (shield: 0 inputs, full unshield: 0 outputs).
		{0, 1, Shape{NInputs: 1, NOutputs: 1}},
		{0, 2, Shape{NInputs: 1, NOutputs: 2}},
		{1, 0, Shape{NInputs: 1, NOutputs: 1}},
		{2, 1, Shape{NInputs: 2, NOutputs: 2}},
		{3, 1, Shape{NInputs: 3, NOutputs: 3}},
		{2, 3, Shape{NInputs: 2, NOutputs: 3}},
		{1, 3, Shape{NInputs: 2, NOutputs: 3}},
		{1, 4, Shape{NInputs: 4, NOutputs: 4}},
		{2, 4, Shape{NInputs: 4, NOutputs: 4}},
		{3, 4, Shape{NInputs: 4, NOutputs: 4}},
		{0, 8, Shape{NInputs: 1, NOutputs: 8}},
	}
	for _, tc := range cases {
		got, err := CanonicalShape(tc.nInputs, tc.nOutputs)
		if err != nil {
			t.Fatalf("CanonicalShape(%d, %d): %v", tc.nInputs, tc.nOutputs, err)
		}
		if got != tc.want {
			t.Fatalf("CanonicalShape(%d, %d) = %s, want %s", tc.nInputs, tc.nOutputs, got, tc.want)
		}
	}

	for _, tc := range []struct{ nInputs, nOutputs int }{
		{6, 1}, {1, 9}, {2, 8}, {5, 5}, {4, 5}, {-1, 1}, {1, -1},
	} {
		if _, err := CanonicalShape(tc.nInputs, tc.nOutputs); err == nil {
			t.Fatalf("CanonicalShape(%d, %d) should be rejected", tc.nInputs, tc.nOutputs)
		}
	}
}

// SupportedShapes is the single source of truth, and CanonicalShape relies on
// it being ordered smallest-fit-first: if a later shape fits inside an earlier
// one (NInputs and NOutputs both <=), the smallest-fit search would return an
// oversized shape whose proof can't verify on-chain. Pin the ordering invariant.
func TestSupportedShapesAreSmallestFitOrdered(t *testing.T) {
	for i := range SupportedShapes {
		for j := i + 1; j < len(SupportedShapes); j++ {
			earlier, later := SupportedShapes[i], SupportedShapes[j]
			if later.NInputs <= earlier.NInputs && later.NOutputs <= earlier.NOutputs {
				t.Fatalf("shape %s fits inside earlier %s; smallest-fit order violated", later, earlier)
			}
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
		"zone_program_id",
		"payer_pubkey_hash",
		"input_owner_pk_hashes",
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
