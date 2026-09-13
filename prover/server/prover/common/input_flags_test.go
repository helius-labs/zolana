package common

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
)

// inputFlagsVectorPath is the cross-language known-answer file: the Rust and
// TypeScript packers read the same vectors, so a change here must land with
// both or the three implementations have silently diverged.
const inputFlagsVectorPath = "../../../../test-vectors/input_flags.json"

type inputFlagsVector struct {
	Name              string  `json:"name"`
	AllowDummyInputs  bool    `json:"allow_dummy_inputs"`
	TreeIndexes       []uint8 `json:"tree_indexes"`
	InputFlags        string  `json:"input_flags"`
	InputFlagsDecimal string  `json:"input_flags_decimal"`
}

type inputFlagsVectorFile struct {
	InputTrees int                `json:"input_trees"`
	Vectors    []inputFlagsVector `json:"vectors"`
}

func TestPackInputFlagsMatchesCrossLanguageVectors(t *testing.T) {
	file := readInputFlagsVectors(t)
	if file.InputTrees != txcircuit.InputTrees {
		t.Fatalf("vector input tree count: got %d want %d", file.InputTrees, txcircuit.InputTrees)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("input flags vector file is empty")
	}
	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			want, ok := new(big.Int).SetString(vector.InputFlagsDecimal, 10)
			if !ok {
				t.Fatalf("decode input_flags_decimal %q", vector.InputFlagsDecimal)
			}
			wantBytes, ok := new(big.Int).SetString(vector.InputFlags, 16)
			if !ok {
				t.Fatalf("decode input_flags %q", vector.InputFlags)
			}
			if want.Cmp(wantBytes) != 0 {
				t.Fatalf("vector hex and decimal disagree: 0x%s vs %s", vector.InputFlags, vector.InputFlagsDecimal)
			}
			got, err := PackInputFlags(vector.AllowDummyInputs, treeIndexFields(vector.TreeIndexes))
			if err != nil {
				t.Fatalf("pack input flags: %v", err)
			}
			if got.Cmp(want) != 0 {
				t.Fatalf("input flags mismatch: got %s want %s", got, want)
			}
			if got.BitLen() > 1+txcircuit.TreeIndexBits*len(vector.TreeIndexes) {
				t.Fatalf(
					"input flags 0x%s exceed the %d-bit width of %d inputs",
					got.Text(16), 1+txcircuit.TreeIndexBits*len(vector.TreeIndexes), len(vector.TreeIndexes),
				)
			}
		})
	}
}

// The packed layout is reconstructible: bit 0 is the policy and each 3-bit
// field holds one input's index, which is what the circuit decodes.
func TestPackInputFlagsLayoutIsRecoverable(t *testing.T) {
	indexes := []*big.Int{big.NewInt(0), big.NewInt(4), big.NewInt(2)}
	flags, err := PackInputFlags(true, indexes)
	if err != nil {
		t.Fatalf("pack input flags: %v", err)
	}
	if flags.Bit(0) != 1 {
		t.Fatal("dummy policy bit is not set")
	}
	for i, want := range indexes {
		got := new(big.Int).Rsh(flags, uint(1+txcircuit.TreeIndexBits*i))
		got.And(got, big.NewInt((1<<txcircuit.TreeIndexBits)-1))
		if got.Cmp(want) != 0 {
			t.Fatalf("input %d tree index: got %s want %s", i, got, want)
		}
	}
}

func TestPackInputFlagsRejectsUnrepresentableIndex(t *testing.T) {
	for _, index := range []*big.Int{nil, big.NewInt(-1), big.NewInt(1 << txcircuit.TreeIndexBits)} {
		if _, err := PackInputFlags(true, []*big.Int{big.NewInt(0), index}); err == nil {
			t.Fatalf("expected tree index %v to be rejected", index)
		}
	}
}

func TestValidateInputFlags(t *testing.T) {
	slots := []*big.Int{big.NewInt(0), big.NewInt(1)}
	flags, err := PackInputFlags(true, slots)
	if err != nil {
		t.Fatalf("pack input flags: %v", err)
	}
	if err := ValidateInputFlags(flags, slots); err != nil {
		t.Fatalf("packed flags rejected: %v", err)
	}
	// Flags that publish a different routing than the request's private
	// selectors are a request error, not a proving failure.
	if err := ValidateInputFlags(flags, []*big.Int{big.NewInt(0), big.NewInt(2)}); err == nil {
		t.Fatal("expected a tree index mismatch to be rejected")
	}
	// Nothing may live above the packed width.
	wide := new(big.Int).SetBit(flags, 1+txcircuit.TreeIndexBits*len(slots), 1)
	if err := ValidateInputFlags(wide, slots); err == nil {
		t.Fatal("expected a bit above the packed width to be rejected")
	}
	if err := ValidateInputFlags(nil, slots); err == nil {
		t.Fatal("expected missing input flags to be rejected")
	}
	if err := ValidateInputFlags(big.NewInt(-1), slots); err == nil {
		t.Fatal("expected negative input flags to be rejected")
	}
}

func treeIndexFields(indexes []uint8) []*big.Int {
	out := make([]*big.Int, len(indexes))
	for i, index := range indexes {
		out[i] = new(big.Int).SetUint64(uint64(index))
	}
	return out
}

func readInputFlagsVectors(t *testing.T) inputFlagsVectorFile {
	t.Helper()
	bytes, err := os.ReadFile(inputFlagsVectorPath)
	if err != nil {
		t.Fatalf("read input flags vectors: %v", err)
	}
	var file inputFlagsVectorFile
	if err := json.Unmarshal(bytes, &file); err != nil {
		t.Fatalf("decode input flags vectors: %v", err)
	}
	return file
}
