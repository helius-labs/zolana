package protocol

import (
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"testing"

	"zolana/prover/prover-test/spp/parse"
)

// The public input hash vectors are cross-language known answers: the Rust
// program tests reassemble the same preimage from these files, so a change here
// must land together with the Rust side or the two implementations have
// silently diverged.
const (
	publicInputHashVectorPath     = "../testdata/public_input_hash_vector.json"
	publicInputHashVector36x2Path = "../testdata/public_input_hash_vector_36x2.json"
)

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
	AllowDummyInputs    string           `json:"allow_dummy_inputs"`
	SignerPkHashes      []string         `json:"signer_pk_hashes"`
	OutputOwnerPkHashes []string         `json:"output_owner_pk_hashes"`
	PublicInputHash     string           `json:"public_input_hash"`
}

type publicInputHashVectorShape struct {
	nInputs      int
	nOutputs     int
	inputSigners int
}

var publicInputHashVectorFiles = map[string]publicInputHashVectorShape{
	publicInputHashVectorPath:     {nInputs: 2, nOutputs: 3, inputSigners: 2},
	publicInputHashVector36x2Path: {nInputs: 36, nOutputs: 2, inputSigners: 2},
}

// TestWritePublicInputHashVectors is the UPDATE_VECTORS=1 escape hatch: it
// rewrites the checked-in known answers after a deliberate preimage change. The
// struct field order is the file's key order, so the files stay readable in
// wire order.
func TestWritePublicInputHashVectors(t *testing.T) {
	if os.Getenv("UPDATE_VECTORS") != "1" {
		t.Skip("set UPDATE_VECTORS=1 to regenerate the public input hash vectors")
	}
	for path, shape := range publicInputHashVectorFiles {
		vector := buildPublicInputHashVector(t, shape)
		bytes, err := json.MarshalIndent(vector, "", "  ")
		if err != nil {
			t.Fatalf("encode %s: %v", path, err)
		}
		if err := os.WriteFile(path, append(bytes, '\n'), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func TestPublicInputHashVectorsMatchTheProducer(t *testing.T) {
	for path, shape := range publicInputHashVectorFiles {
		got := readPublicInputHashVector(t, path)
		want := buildPublicInputHashVector(t, shape)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s is stale: regenerate with UPDATE_VECTORS=1", path)
		}
	}
}

func TestPublicInputHashKnownAnswerVector(t *testing.T) {
	for path := range publicInputHashVectorFiles {
		vector := readPublicInputHashVector(t, path)
		if len(vector.PublicAssets) != NPublicSlots || len(vector.PublicAmounts) != NPublicSlots {
			t.Fatalf("%s public slot count: got %d assets and %d amounts, want %d",
				path, len(vector.PublicAssets), len(vector.PublicAmounts), NPublicSlots)
		}
		inputs := inputsFromVector(t, vector)
		inputs.BindOutputOwnerTags = true
		got, err := PublicInputHash(inputs)
		if err != nil {
			t.Fatalf("%s public input hash: %v", path, err)
		}

		want := parseField(t, vector.PublicInputHash)
		if got.Cmp(want) != 0 {
			t.Fatalf("%s public input hash mismatch:\ngot  0x%s\nwant 0x%s", path, parse.FieldHex(got), parse.FieldHex(want))
		}
	}
}

// buildPublicInputHashVector produces a vector from small tagged values so the
// preimage is readable by eye. Tree slots are populated for the first
// min(nInputs, InputTrees) trees and zero-padded to InputTrees, the layout SPP
// publishes.
func buildPublicInputHashVector(t *testing.T, shape publicInputHashVectorShape) publicInputHashVector {
	t.Helper()
	if shape.inputSigners > shape.nInputs {
		t.Fatalf("vector shape declares %d input signers for %d inputs", shape.inputSigners, shape.nInputs)
	}
	tag := func(value int64) string {
		return "0x" + parse.FieldHex(big.NewInt(value))
	}
	run := func(base int64, count int) []string {
		out := make([]string, count)
		for i := range out {
			out[i] = tag(base + int64(i))
		}
		return out
	}
	signers := make([]string, shape.nInputs+1)
	signers[0] = tag(1201)
	for i := range signers[1:] {
		if i < shape.inputSigners {
			signers[i+1] = tag(1301 + int64(i))
		} else {
			signers[i+1] = tag(0)
		}
	}
	populatedTrees := shape.nInputs
	if populatedTrees > InputTrees {
		populatedTrees = InputTrees
	}
	treeSlots := make([]treeSlotVector, InputTrees)
	for k := range treeSlots {
		if k < populatedTrees {
			treeSlots[k] = treeSlotVector{
				ID:            tag(7 + 10*int64(k)),
				UtxoRoot:      tag(301 + int64(k)),
				NullifierRoot: tag(401 + int64(k)),
			}
		} else {
			treeSlots[k] = treeSlotVector{ID: tag(0), UtxoRoot: tag(0), NullifierRoot: tag(0)}
		}
	}
	vector := publicInputHashVector{
		Nullifiers:          run(101, shape.nInputs),
		OutputUtxoHashes:    run(201, shape.nOutputs),
		TreeSlots:           treeSlots,
		OutputTreeID:        tag(11),
		PrivateTxHash:       tag(501),
		ExternalDataHash:    tag(701),
		PublicAssets:        make([]string, NPublicSlots),
		PublicAmounts:       make([]string, NPublicSlots),
		RingProgramID:       tag(1501),
		AllowDummyInputs:    tag(1),
		SignerPkHashes:      signers,
		OutputOwnerPkHashes: run(1537, shape.nOutputs),
	}
	for i := 0; i < NPublicSlots; i++ {
		vector.PublicAssets[i] = tag(801 + 200*int64(i))
		vector.PublicAmounts[i] = tag(901 + 200*int64(i))
	}
	inputs := inputsFromVector(t, vector)
	inputs.BindOutputOwnerTags = true
	hash, err := PublicInputHash(inputs)
	if err != nil {
		t.Fatalf("public input hash: %v", err)
	}
	vector.PublicInputHash = "0x" + parse.FieldHex(hash)
	return vector
}

// The preimage carries exactly InputTrees slots. A shorter or longer list is a
// different commitment shape, so it must not silently hash.
func TestPublicInputHashRejectsWrongTreeSlotCount(t *testing.T) {
	inputs := inputsFromVector(t, readPublicInputHashVector(t, publicInputHashVectorPath))
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
	inputs := inputsFromVector(t, readPublicInputHashVector(t, publicInputHashVectorPath))
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
		mustHashChain(t, inputs.Nullifiers),
		mustHashChain(t, inputs.OutputUtxoHashes),
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
	fields = append(fields, inputs.RingProgramID, signerChain, inputs.AllowDummyInputs)
	want := mustHashChain(t, fields)
	if got.Cmp(want) != 0 {
		t.Fatalf("inserted preimage mismatch:\ngot  0x%s\nwant 0x%s", parse.FieldHex(got), parse.FieldHex(want))
	}
}

func TestCustomRingPublicInputHashDoesNotBindPrivateOutputOwners(t *testing.T) {
	vector := readPublicInputHashVector(t, publicInputHashVectorPath)
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
		AllowDummyInputs:    parseField(t, vector.AllowDummyInputs),
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

func readPublicInputHashVector(t *testing.T, path string) publicInputHashVector {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read public input hash vector: %v", err)
	}
	var vector publicInputHashVector
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatalf("decode public input hash vector: %v", err)
	}
	return vector
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
