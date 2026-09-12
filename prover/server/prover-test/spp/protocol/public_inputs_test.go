package protocol

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"zolana/prover/prover-test/spp/parse"
)

// publicInputHashVectorPath is the cross-language known-answer vector: the Rust
// program tests reassemble the same preimage from this file, so a change here
// must land together with the Rust side or the two implementations have
// silently diverged.
const publicInputHashVectorPath = "../testdata/public_input_hash_vector.json"

type treeSlotVector struct {
	ID            string `json:"id"`
	UtxoRoot      string `json:"utxo_root"`
	NullifierRoot string `json:"nullifier_root"`
}

type publicInputHashVector struct {
	Nullifiers          []string         `json:"nullifiers"`
	OutputUtxoHashes    []string         `json:"output_utxo_hashes"`
	TreeSlots           []treeSlotVector `json:"tree_slots"`
	OutputTreeID        string           `json:"output_tree_id"`
	PrivateTxHash       string           `json:"private_tx_hash"`
	ExternalDataHash    string           `json:"external_data_hash"`
	PublicAssets        []string         `json:"public_assets"`
	PublicAmounts       []string         `json:"public_amounts"`
	RingProgramID       string           `json:"ring_program_id"`
	InputFlags          string           `json:"input_flags"`
	SignerPkHashes      []string         `json:"signer_pk_hashes"`
	OutputOwnerPkHashes []string         `json:"output_owner_pk_hashes"`
	PublicInputHash     string           `json:"public_input_hash"`
}

func TestPublicInputHashKnownAnswerVector(t *testing.T) {
	vector := readPublicInputHashVector(t)
	if len(vector.PublicAssets) != NPublicSlots || len(vector.PublicAmounts) != NPublicSlots {
		t.Fatalf("vector public slot count: got %d assets and %d amounts, want %d",
			len(vector.PublicAssets), len(vector.PublicAmounts), NPublicSlots)
	}
	inputs := inputsFromVector(t, vector)
	inputs.BindOutputOwnerTags = true
	got, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatalf("public input hash: %v", err)
	}

	if os.Getenv("UPDATE_VECTORS") == "1" {
		vector.PublicInputHash = "0x" + parse.FieldHex(got)
		writePublicInputHashVector(t, vector)
		t.Skip("rewrote the public input hash vector; rerun without UPDATE_VECTORS")
	}

	want := parseField(t, vector.PublicInputHash)
	if got.Cmp(want) != 0 {
		t.Fatalf("public input hash mismatch:\ngot  0x%s\nwant 0x%s", parse.FieldHex(got), parse.FieldHex(want))
	}
}

// The preimage carries exactly InputTrees slots. A shorter or longer list is a
// different commitment shape, so it must not silently hash.
func TestPublicInputHashRejectsWrongTreeSlotCount(t *testing.T) {
	inputs := inputsFromVector(t, readPublicInputHashVector(t))
	padded, err := PadTreeSlots()
	if err != nil {
		t.Fatal(err)
	}
	tooMany := append(append([]TreeSlot{}, padded...), ZeroTreeSlot())
	for _, slots := range [][]TreeSlot{nil, padded[:InputTrees-1], tooMany} {
		inputs.TreeSlots = slots
		if _, err := PublicInputHash(inputs); err == nil {
			t.Fatalf("expected %d tree slots to be rejected", len(slots))
		}
	}

	inputs.TreeSlots = padded
	inputs.OutputTreeID = nil
	if _, err := PublicInputHash(inputs); err == nil {
		t.Fatal("expected a missing output tree id to be rejected")
	}
}

// PreimageAfterPrivateTxHash is the P256 rail's insertion point: its elements
// land directly after private_tx_hash and before external_data_hash, so the
// two rails cannot reinterpret each other's preimage.
func TestPublicInputHashInsertsPreimageAfterPrivateTxHash(t *testing.T) {
	inputs := inputsFromVector(t, readPublicInputHashVector(t))
	base, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatal(err)
	}

	inserted := []*big.Int{big.NewInt(0x1111), big.NewInt(0x2222)}
	inputs.PreimageAfterPrivateTxHash = inserted
	got, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(base) == 0 {
		t.Fatal("inserted preimage elements did not change the public input hash")
	}

	fields := []*big.Int{
		mustHashChain4(t, inputs.Nullifiers),
		mustHashChain4(t, inputs.OutputUtxoHashes),
		mustTreeSlotsHashChain(t, inputs.TreeSlots),
		inputs.OutputTreeID,
		inputs.PrivateTxHash,
		inserted[0],
		inserted[1],
		inputs.ExternalDataHash,
	}
	for i := 0; i < NPublicSlots; i++ {
		fields = append(fields, inputs.PublicAssets[i], inputs.PublicAmounts[i])
	}
	signerChain, err := RightHashChain(inputs.SignerPkHashes)
	if err != nil {
		t.Fatal(err)
	}
	fields = append(fields, inputs.RingProgramID, signerChain, inputs.InputFlags)
	want := mustHashChain4(t, fields)
	if got.Cmp(want) != 0 {
		t.Fatalf("inserted preimage mismatch:\ngot  0x%s\nwant 0x%s", parse.FieldHex(got), parse.FieldHex(want))
	}
}

func TestCustomRingPublicInputHashDoesNotBindPrivateOutputOwners(t *testing.T) {
	vector := readPublicInputHashVector(t)
	inputs := inputsFromVector(t, vector)
	inputs.BindOutputOwnerTags = false

	first, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatalf("first public input hash: %v", err)
	}
	inputs.BindOutputOwnerTags = true
	boundBefore, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatalf("first bound public input hash: %v", err)
	}

	inputs.OutputOwnerPkHashes[0] = new(big.Int).Add(inputs.OutputOwnerPkHashes[0], big.NewInt(1))
	inputs.BindOutputOwnerTags = false
	second, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatalf("second public input hash: %v", err)
	}
	if first.Cmp(second) != 0 {
		t.Fatal("custom-ring public input hash changed with private output owner")
	}

	inputs.BindOutputOwnerTags = true
	boundAfter, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatalf("second bound public input hash: %v", err)
	}
	if boundBefore.Cmp(boundAfter) == 0 {
		t.Fatal("default-ring public input hash did not change with public output owner")
	}
}

func inputsFromVector(t *testing.T, vector publicInputHashVector) PublicInputs {
	t.Helper()
	inputs := PublicInputs{
		Nullifiers:          parseFields(t, vector.Nullifiers),
		OutputUtxoHashes:    parseFields(t, vector.OutputUtxoHashes),
		TreeSlots:           parseTreeSlots(t, vector.TreeSlots),
		OutputTreeID:        parseField(t, vector.OutputTreeID),
		PrivateTxHash:       parseField(t, vector.PrivateTxHash),
		ExternalDataHash:    parseField(t, vector.ExternalDataHash),
		RingProgramID:       parseField(t, vector.RingProgramID),
		InputFlags:          parseField(t, vector.InputFlags),
		SignerPkHashes:      parseFields(t, vector.SignerPkHashes),
		OutputOwnerPkHashes: parseFields(t, vector.OutputOwnerPkHashes),
	}
	for i := 0; i < NPublicSlots; i++ {
		inputs.PublicAssets[i] = parseField(t, vector.PublicAssets[i])
		inputs.PublicAmounts[i] = parseField(t, vector.PublicAmounts[i])
	}
	return inputs
}

func parseTreeSlots(t *testing.T, slots []treeSlotVector) []TreeSlot {
	t.Helper()
	out := make([]TreeSlot, len(slots))
	for i, slot := range slots {
		out[i] = TreeSlot{
			ID:            parseField(t, slot.ID),
			UtxoRoot:      parseField(t, slot.UtxoRoot),
			NullifierRoot: parseField(t, slot.NullifierRoot),
		}
	}
	return out
}

func mustTreeSlotsHashChain(t *testing.T, slots []TreeSlot) *big.Int {
	t.Helper()
	value, err := TreeSlotsHashChain(slots)
	return mustHash(t, value, err)
}

func TestRightHashChainFoldsFromThePaddedSuffix(t *testing.T) {
	inputs := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(0)}
	got, err := RightHashChain(inputs)
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := HashChain([]*big.Int{big.NewInt(2), big.NewInt(0)})
	if err != nil {
		t.Fatal(err)
	}
	want, err := HashChain([]*big.Int{big.NewInt(1), suffix})
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("right hash chain mismatch: got %s want %s", got, want)
	}
	left, err := HashChain(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(left) == 0 {
		t.Fatal("three-element right fold unexpectedly equals left fold")
	}
}

func readPublicInputHashVector(t *testing.T) publicInputHashVector {
	t.Helper()
	bytes, err := os.ReadFile(publicInputHashVectorPath)
	if err != nil {
		t.Fatalf("read public input hash vector: %v", err)
	}
	var vector publicInputHashVector
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatalf("decode public input hash vector: %v", err)
	}
	return vector
}

// writePublicInputHashVector is the UPDATE_VECTORS=1 escape hatch: it rewrites
// the checked-in known answer after a deliberate preimage change. The struct
// field order is the file's key order, so the file stays readable in wire
// order.
func writePublicInputHashVector(t *testing.T, vector publicInputHashVector) {
	t.Helper()
	encoded, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatalf("encode public input hash vector: %v", err)
	}
	if err := os.WriteFile(publicInputHashVectorPath, append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write public input hash vector: %v", err)
	}
}

func parseFields(t *testing.T, values []string) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = parseField(t, value)
	}
	return out
}

func parseField(t *testing.T, value string) *big.Int {
	t.Helper()
	out, err := parse.Field(value)
	if err != nil {
		t.Fatalf("parse field %q: %v", value, err)
	}
	return out
}
