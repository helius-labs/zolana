package protocol

import "testing"

func TestSupportedShapes(t *testing.T) {
	grid := map[int][]int{
		2:  {1, 2, 3, 4, 5, 6, 8, 12, 16, 24, 32, 40, 48, 51},
		4:  {1, 2, 3, 4, 5, 6, 8, 12, 16, 24},
		8:  {1, 2, 3, 4, 5, 6, 8, 12, 16},
		16: {1, 2, 4, 5, 8},
	}
	count := 0
	for nOutputs, inputCounts := range grid {
		for _, nInputs := range inputCounts {
			shape := Shape{NInputs: nInputs, NOutputs: nOutputs}
			if err := shape.Validate(); err != nil {
				t.Fatalf("expected shape %s to be supported: %v", shape, err)
			}
			count++
		}
	}
	if len(SupportedShapes) != count {
		t.Fatalf("supported shape count: got %d want %d", len(SupportedShapes), count)
	}
	if len(AutoShapes) != len(SupportedShapes) {
		t.Fatalf("automatic selection reaches %d of %d shapes", len(AutoShapes), len(SupportedShapes))
	}
}

func TestUnsupportedShapes(t *testing.T) {
	tests := []Shape{
		{NInputs: 0, NOutputs: 1},
		{NInputs: 0, NOutputs: 2},
		{NInputs: 1, NOutputs: 0},
		{NInputs: 1, NOutputs: 1},
		{NInputs: 2, NOutputs: 3},
		{NInputs: 3, NOutputs: 3},
		{NInputs: 4, NOutputs: 3},
		{NInputs: 5, NOutputs: 3},
		{NInputs: 36, NOutputs: 2},
		{NInputs: 7, NOutputs: 2},
		{NInputs: 52, NOutputs: 2},
		{NInputs: 32, NOutputs: 4},
		{NInputs: 24, NOutputs: 8},
		{NInputs: 6, NOutputs: 16},
		{NInputs: 1, NOutputs: 32},
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
		{1, 2, Shape{NInputs: 1, NOutputs: 2}},
		{2, 2, Shape{NInputs: 2, NOutputs: 2}},
		{4, 4, Shape{NInputs: 4, NOutputs: 4}},
		{5, 4, Shape{NInputs: 5, NOutputs: 4}},
		{1, 8, Shape{NInputs: 1, NOutputs: 8}},
		{1, 16, Shape{NInputs: 1, NOutputs: 16}},
		{8, 16, Shape{NInputs: 8, NOutputs: 16}},
		{16, 8, Shape{NInputs: 16, NOutputs: 8}},
		{24, 4, Shape{NInputs: 24, NOutputs: 4}},
		{51, 2, Shape{NInputs: 51, NOutputs: 2}},
		// Smaller arities map to the cheapest shape with capacity; the unused
		// slots are dummy-padded (shield: 0 inputs, full unshield: 0 outputs).
		{0, 1, Shape{NInputs: 1, NOutputs: 2}},
		{0, 2, Shape{NInputs: 1, NOutputs: 2}},
		{1, 0, Shape{NInputs: 1, NOutputs: 2}},
		{1, 1, Shape{NInputs: 1, NOutputs: 2}},
		{1, 3, Shape{NInputs: 1, NOutputs: 4}},
		{2, 3, Shape{NInputs: 2, NOutputs: 4}},
		{3, 3, Shape{NInputs: 3, NOutputs: 4}},
		{4, 3, Shape{NInputs: 4, NOutputs: 4}},
		{5, 3, Shape{NInputs: 5, NOutputs: 4}},
		{1, 5, Shape{NInputs: 1, NOutputs: 8}},
		{2, 5, Shape{NInputs: 2, NOutputs: 8}},
		{1, 9, Shape{NInputs: 1, NOutputs: 16}},
		{2, 9, Shape{NInputs: 2, NOutputs: 16}},
		{3, 9, Shape{NInputs: 4, NOutputs: 16}},
		{6, 9, Shape{NInputs: 8, NOutputs: 16}},
		{7, 1, Shape{NInputs: 8, NOutputs: 2}},
		{9, 2, Shape{NInputs: 12, NOutputs: 2}},
		{13, 5, Shape{NInputs: 16, NOutputs: 8}},
		{17, 3, Shape{NInputs: 24, NOutputs: 4}},
		{25, 2, Shape{NInputs: 32, NOutputs: 2}},
		{36, 2, Shape{NInputs: 40, NOutputs: 2}},
		{49, 1, Shape{NInputs: 51, NOutputs: 2}},
	}
	for _, tc := range cases {
		got, err := CanonicalShape(tc.nInputs, tc.nOutputs)
		if err != nil {
			t.Fatalf("CanonicalShape(%d, %d): %v", tc.nInputs, tc.nOutputs, err)
		}
		if got != tc.want {
			t.Fatalf("CanonicalShape(%d, %d) = %s, want %s", tc.nInputs, tc.nOutputs, got, tc.want)
		}
		smallest, err := SmallestSupportedShape(tc.nInputs, tc.nOutputs)
		if err != nil || smallest != got {
			t.Fatalf("SmallestSupportedShape(%d, %d) = %s, %v; want %s", tc.nInputs, tc.nOutputs, smallest, err, got)
		}
	}

	for _, tc := range []struct{ nInputs, nOutputs int }{
		{52, 1}, {1, 17}, {9, 16}, {17, 8}, {25, 3}, {33, 3}, {-1, 1}, {1, -1},
	} {
		if _, err := CanonicalShape(tc.nInputs, tc.nOutputs); err == nil {
			t.Fatalf("CanonicalShape(%d, %d) should be rejected", tc.nInputs, tc.nOutputs)
		}
	}
}

// The smallest-fit search returns the first shape that holds a transaction, so
// the list must be sorted by proving cost for that shape to be the cheapest
// fit. Measured on the confidential rail: about 22.7k constraints per input and
// 2k per output; the P256 rail adds a constant on top.
func TestSupportedShapesAreCostOrdered(t *testing.T) {
	cost := func(s Shape) int { return 22700*s.NInputs + 2050*s.NOutputs }
	for i := 1; i < len(SupportedShapes); i++ {
		earlier, later := SupportedShapes[i-1], SupportedShapes[i]
		if cost(later) <= cost(earlier) {
			t.Fatalf("shape %s is not more expensive than earlier %s", later, earlier)
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
		"tree_slots",
		"output_tree_id",
		"private_tx_hash",
		"external_data_hash",
		"public_asset_0",
		"public_amount_0",
		"public_asset_1",
		"public_amount_1",
		"public_asset_2",
		"public_amount_2",
		"ring_program_id",
		"signer_pk_hashes",
		"input_flags",
		"output_owner_pk_hashes",
		"cache_tree_id",
		"cache_read_hash_chain",
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

func TestShapeSignerWidth(t *testing.T) {
	cases := map[Shape]int{
		{NInputs: 1, NOutputs: 2}:  2,
		{NInputs: 5, NOutputs: 4}:  6,
		{NInputs: 24, NOutputs: 2}: 25,
		{NInputs: 32, NOutputs: 2}: 29,
		{NInputs: 51, NOutputs: 2}: 10,
	}
	for shape, want := range cases {
		if got := shape.SignerWidth(); got != want {
			t.Fatalf("%s signer width: got %d want %d", shape, got, want)
		}
	}
	widest := 0
	for _, shape := range SupportedShapes {
		if OwnerSignerSlots(shape.NInputs)+shape.NInputs+FixedTransactAddresses > MaxTransactionAddresses {
			t.Fatalf("%s owner signer slots exceed the address limit", shape)
		}
		widest = max(widest, shape.SignerWidth())
	}
	if widest != 29 {
		t.Fatalf("widest signer vector: got %d want 29 (MAX_SIGNERS)", widest)
	}
}
