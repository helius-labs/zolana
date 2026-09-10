package merge

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

// defaultTestNInputs is the merge shape these parameter tests build. Every
// supported count shares one witness-assignment path, so one shape covers it;
// TestValidateShapeAcceptsEverySupportedCount pins the set itself.
const defaultTestNInputs = 8

// TestMergeParametersJSONRoundTrip checks the wire format the Rust client
// produces decodes back to identical parameters (shape, paths, and all fields).
func TestMergeParametersJSONRoundTrip(t *testing.T) {
	p := sampleParams()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got MergeParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := got.ValidateShape(); err != nil {
		t.Fatalf("validate shape after round trip: %v", err)
	}
	if got.PublicInputHash.Cmp(p.PublicInputHash) != 0 {
		t.Fatalf("public input hash mismatch: got %s want %s", got.PublicInputHash, p.PublicInputHash)
	}
	if len(got.Inputs) != len(p.Inputs) {
		t.Fatalf("input count mismatch: got %d want %d", len(got.Inputs), len(p.Inputs))
	}
	if got.OutputTreeID.Cmp(p.OutputTreeID) != 0 {
		t.Fatalf("output tree id mismatch: got %s want %s", got.OutputTreeID, p.OutputTreeID)
	}
	if len(got.TreeSlots) != len(p.TreeSlots) {
		t.Fatalf("tree slot count mismatch: got %d want %d", len(got.TreeSlots), len(p.TreeSlots))
	}
	for k := range p.TreeSlots {
		want, have := p.TreeSlots[k], got.TreeSlots[k]
		if have.ID.Cmp(want.ID) != 0 ||
			have.UtxoRoot.Cmp(want.UtxoRoot) != 0 ||
			have.NullifierRoot.Cmp(want.NullifierRoot) != 0 {
			t.Fatalf("tree slot %d mismatch: got %v want %v", k, have, want)
		}
	}
	for i := range p.Inputs {
		if got.Inputs[i].TreeSlot.Cmp(p.Inputs[i].TreeSlot) != 0 {
			t.Fatalf("input %d tree slot mismatch: got %s want %s", i, got.Inputs[i].TreeSlot, p.Inputs[i].TreeSlot)
		}
	}
}

// TestMergeParametersJSONKeys pins the request schema the Rust client encodes:
// tree identity is published once per slot and selected privately per input, so
// the per-input roots must be gone, and no field carries the private tx
// blinding (the circuit derives it from UserNullifierSecret).
func TestMergeParametersJSONKeys(t *testing.T) {
	data, err := json.Marshal(sampleParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	for _, key := range []string{"treeSlots", "outputTreeId"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing top-level key %q in %s", key, data)
		}
	}
	if _, ok := fields["privateTxBlinding"]; ok {
		t.Fatal("privateTxBlinding must not be on the wire; the circuit derives it")
	}

	var slots []map[string]json.RawMessage
	if err := json.Unmarshal(fields["treeSlots"], &slots); err != nil {
		t.Fatalf("unmarshal tree slots: %v", err)
	}
	if len(slots) != transaction.InputTrees {
		t.Fatalf("tree slot count: got %d want %d", len(slots), transaction.InputTrees)
	}
	for _, key := range []string{"id", "utxoRoot", "nullifierRoot"} {
		if _, ok := slots[0][key]; !ok {
			t.Fatalf("missing treeSlots[0].%s", key)
		}
	}

	var inputs []map[string]json.RawMessage
	if err := json.Unmarshal(fields["inputs"], &inputs); err != nil {
		t.Fatalf("unmarshal inputs: %v", err)
	}
	if _, ok := inputs[0]["treeSlot"]; !ok {
		t.Fatal("missing inputs[0].treeSlot")
	}
	for _, key := range []string{"utxoTreeRoot", "nullifierTreeRoot"} {
		if _, ok := inputs[0][key]; ok {
			t.Fatalf("inputs[0].%s must not be on the wire; roots live in treeSlots", key)
		}
	}
}

// TestMergeParametersRejectMissingUserNullifierSecret guards the required
// field. The secret seeds both the private tx blinding and the merged output's
// blinding, so defaulting an absent one to zero would hand an observer both.
func TestMergeParametersRejectMissingUserNullifierSecret(t *testing.T) {
	data, err := json.Marshal(sampleParams())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	delete(fields, "userNullifierSecret")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}

	var got MergeParameters
	if err := json.Unmarshal(stripped, &got); err == nil {
		t.Fatal("expected an omitted userNullifierSecret to be rejected")
	}
}

// TestMergeParametersValidateShapeTreeSlots checks ValidateShape rejects a
// request the circuit's SelectTreeSlot would only fail on as an opaque proving
// error: a slot list of the wrong length or an input selecting a slot that does
// not exist.
func TestMergeParametersValidateShapeTreeSlots(t *testing.T) {
	t.Run("wrong slot count", func(t *testing.T) {
		p := sampleParams()
		p.TreeSlots = p.TreeSlots[:transaction.InputTrees-1]
		err := p.ValidateShape()
		if err == nil {
			t.Fatal("expected a short tree slot list to be rejected")
		}
		if !strings.Contains(err.Error(), "tree slot count mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("input slot out of range", func(t *testing.T) {
		p := sampleParams()
		p.Inputs[0].TreeSlot = big.NewInt(int64(transaction.InputTrees))
		err := p.ValidateShape()
		if err == nil {
			t.Fatal("expected an out-of-range input tree slot to be rejected")
		}
		if !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("input selects unused slot", func(t *testing.T) {
		p := sampleParams()
		p.Inputs[0].TreeSlot = big.NewInt(1)
		err := p.ValidateShape()
		if err == nil {
			t.Fatal("expected an unused tree slot to be rejected")
		}
		if !strings.Contains(err.Error(), "unused tree slot") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing output tree id", func(t *testing.T) {
		p := sampleParams()
		p.OutputTreeID = nil
		if err := p.ValidateShape(); err == nil {
			t.Fatal("expected a missing outputTreeId to be rejected")
		}
	})
}

func TestMergeParametersCreateCompleteWitness(t *testing.T) {
	params := sampleParams()
	for _, circuitType := range []common.CircuitType{
		common.MergeCircuitType,
		common.MergeRingCircuitType,
	} {
		t.Run(string(circuitType), func(t *testing.T) {
			params.CircuitType = circuitType
			assignment, err := params.CreateWitness()
			if err != nil {
				t.Fatalf("create assignment: %v", err)
			}
			if _, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("create gnark witness: %v", err)
			}
		})
	}
}

func sampleParams() *MergeParameters {
	inputs := make([]InputParams, defaultTestNInputs)
	for i := range inputs {
		inputs[i] = InputParams{
			Domain:                   big.NewInt(3),
			Amount:                   big.NewInt(5),
			Blinding:                 big.NewInt(7),
			RingDataHash:             big.NewInt(0),
			StatePathElements:        zeros(transaction.StateTreeHeight),
			StatePathIndex:           big.NewInt(0),
			NullifierLowValue:        big.NewInt(0),
			NullifierNextValue:       big.NewInt(0),
			NullifierLowPathElements: zeros(transaction.NullifierTreeHeight),
			NullifierLowPathIndex:    big.NewInt(0),
			TreeSlot:                 big.NewInt(0),
			Nullifier:                big.NewInt(int64(100 + i)),
		}
	}
	// Only slot 0 is in use; the remaining slots stay all zero, which is the
	// unused-slot encoding no input may select.
	treeSlots := make([]common.TreeSlotParams, transaction.InputTrees)
	for k := range treeSlots {
		treeSlots[k] = common.TreeSlotParams{
			ID:            big.NewInt(0),
			UtxoRoot:      big.NewInt(0),
			NullifierRoot: big.NewInt(0),
		}
	}
	treeSlots[0] = common.TreeSlotParams{
		ID:            big.NewInt(7),
		UtxoRoot:      big.NewInt(11),
		NullifierRoot: big.NewInt(13),
	}
	return &MergeParameters{
		Inputs:              inputs,
		Output:              OutputParams{RingDataHash: big.NewInt(0), Hash: big.NewInt(0x9999)},
		TreeSlots:           treeSlots,
		OutputTreeID:        big.NewInt(11),
		Asset:               big.NewInt(1),
		OwnerPkHash:         big.NewInt(0x1212),
		UserNullifierPk:     big.NewInt(0x3333),
		UserNullifierSecret: big.NewInt(0x4444),
		OutputRingDataHash:  big.NewInt(0),
		ExternalDataHash:    big.NewInt(0x6666),
		PrivateTxHash:       big.NewInt(0x7777),
		AllowDummyInputs:    big.NewInt(1),
		PublicInputHash:     big.NewInt(0x8888),
		RingProgramID:       big.NewInt(0),
	}
}

func zeros(n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

// TestValidateShapeAcceptsEverySupportedCount pins the shape gate: merge
// parameters carry no shape field, so the declared input count is the shape and
// ValidateShape is the only place an unsupported count is refused.
func TestValidateShapeAcceptsEverySupportedCount(t *testing.T) {
	for _, nInputs := range SupportedNInputs() {
		params := sampleParams()
		params.Inputs = resizeInputs(params.Inputs, int(nInputs))
		if err := params.ValidateShape(); err != nil {
			t.Fatalf("supported count %d rejected: %v", nInputs, err)
		}
	}
}

func TestValidateShapeRejectsUnsupportedCount(t *testing.T) {
	for _, nInputs := range []int{0, 1, 7, 9, 35, 37} {
		params := sampleParams()
		params.Inputs = resizeInputs(params.Inputs, nInputs)
		if err := params.ValidateShape(); err == nil {
			t.Fatalf("unsupported count %d accepted", nInputs)
		}
	}
}

// resizeInputs grows or shrinks a parameter set to n slots, repeating the
// sample slot; only the count matters to ValidateShape.
func resizeInputs(inputs []InputParams, n int) []InputParams {
	out := make([]InputParams, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, inputs[i%len(inputs)])
	}
	return out
}
