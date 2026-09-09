package transfereddsaonly

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// TestTransferParametersJSONKeys pins the request schema the Rust client
// encodes: tree identity is published once per slot and selected privately per
// input, so the per-input roots must be gone, and the transaction's randomness
// travels as one root seed the circuit expands.
func TestTransferParametersJSONKeys(t *testing.T) {
	data, err := json.Marshal(sampleTransferParams(RingVariant))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	for _, key := range []string{"treeSlots", "outputTreeId", "blindingSeed"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing top-level key %q in %s", key, data)
		}
	}
	for _, key := range []string{"outputBlindingSeed", "privateTxBlinding"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("%s must not be on the wire; the circuit derives it from blindingSeed", key)
		}
	}

	var slots []map[string]json.RawMessage
	if err := json.Unmarshal(fields["treeSlots"], &slots); err != nil {
		t.Fatalf("unmarshal tree slots: %v", err)
	}
	if len(slots) != txcircuit.InputTrees {
		t.Fatalf("tree slot count: got %d want %d", len(slots), txcircuit.InputTrees)
	}
	for _, key := range []string{"id", "utxoRoot", "nullifierRoot"} {
		if _, ok := slots[0][key]; !ok {
			t.Fatalf("missing tree slot key %q", key)
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

// TestTransferParametersDecodeTreeSlots checks the hex wire values map back onto
// the right parameters: every slot keeps its id and both roots, and each input
// keeps the slot index that selects them.
func TestTransferParametersDecodeTreeSlots(t *testing.T) {
	want := sampleTransferParams(RingVariant)
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got TransferParameters
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.TreeSlots) != len(want.TreeSlots) {
		t.Fatalf("tree slot count: got %d want %d", len(got.TreeSlots), len(want.TreeSlots))
	}
	for k := range want.TreeSlots {
		have, expected := got.TreeSlots[k], want.TreeSlots[k]
		if have.ID.Cmp(expected.ID) != 0 ||
			have.UtxoRoot.Cmp(expected.UtxoRoot) != 0 ||
			have.NullifierRoot.Cmp(expected.NullifierRoot) != 0 {
			t.Fatalf("tree slot %d: got %v want %v", k, have, expected)
		}
	}
	for i := range want.Inputs {
		if got.Inputs[i].TreeSlot.Cmp(want.Inputs[i].TreeSlot) != 0 {
			t.Fatalf("input %d tree slot: got %s want %s", i, got.Inputs[i].TreeSlot, want.Inputs[i].TreeSlot)
		}
	}
	if got.OutputTreeID.Cmp(want.OutputTreeID) != 0 {
		t.Fatalf("output tree id: got %s want %s", got.OutputTreeID, want.OutputTreeID)
	}
	if got.BlindingSeed.Cmp(want.BlindingSeed) != 0 {
		t.Fatalf("blinding seed: got %s want %s", got.BlindingSeed, want.BlindingSeed)
	}
}

// TestTransferParametersRejectBlindingSeed guards the one field the whole
// transaction's randomness hangs off. A zero or omitted seed gives an observer
// a known private tx blinding and predictable output blindings, so the request
// must fail at parse time rather than as an unexplained proving error.
func TestTransferParametersRejectBlindingSeed(t *testing.T) {
	data, err := json.Marshal(sampleTransferParams(RingVariant))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	t.Run("omitted", func(t *testing.T) {
		stripped := cloneFields(fields)
		delete(stripped, "blindingSeed")
		assertTransferDecodeFails(t, stripped)
	})

	t.Run("zero", func(t *testing.T) {
		zeroed := cloneFields(fields)
		zeroed["blindingSeed"] = "0x0"
		assertTransferDecodeFails(t, zeroed)
	})
}

// TestTransferParametersValidateShapeTreeSlots checks ValidateShape rejects
// requests the circuit's SelectTreeSlot would only fail on as an opaque proving
// error.
func TestTransferParametersValidateShapeTreeSlots(t *testing.T) {
	t.Run("wrong slot count", func(t *testing.T) {
		p := sampleTransferParams(RingVariant)
		p.TreeSlots = p.TreeSlots[:txcircuit.InputTrees-1]
		assertShapeError(t, p, "tree slot count mismatch")
	})

	t.Run("input slot out of range", func(t *testing.T) {
		p := sampleTransferParams(RingVariant)
		p.Inputs[0].TreeSlot = big.NewInt(int64(txcircuit.InputTrees))
		assertShapeError(t, p, "out of range")
	})

	t.Run("input selects unused slot", func(t *testing.T) {
		p := sampleTransferParams(RingVariant)
		p.Inputs[0].TreeSlot = big.NewInt(2)
		assertShapeError(t, p, "unused tree slot")
	})

	t.Run("missing output tree id", func(t *testing.T) {
		p := sampleTransferParams(RingVariant)
		p.OutputTreeID = nil
		assertShapeError(t, p, "outputTreeId is required")
	})
}

// TestTransferParametersCreateCompleteWitness catches a witness field the
// variant literals forget to assign: gnark refuses a circuit with an unset
// signal, so a missing TreeSlots, OutputTreeID, or BlindingSeed fails here.
func TestTransferParametersCreateCompleteWitness(t *testing.T) {
	for _, variant := range []Variant{ConfidentialVariant, RingVariant, RingAuthorityVariant} {
		t.Run(string(variant.CircuitType()), func(t *testing.T) {
			params := sampleTransferParams(variant)
			data, err := json.Marshal(params)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded TransferParameters
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if decoded.Variant != variant {
				t.Fatalf("variant: got %d want %d", decoded.Variant, variant)
			}
			if err := decoded.ValidateShape(); err != nil {
				t.Fatalf("validate shape: %v", err)
			}
			assignment, err := decoded.CreateWitness()
			if err != nil {
				t.Fatalf("create assignment: %v", err)
			}
			if _, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("create gnark witness: %v", err)
			}
		})
	}
}

func assertTransferDecodeFails(t *testing.T, fields map[string]any) {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var got TransferParameters
	if err := json.Unmarshal(data, &got); err == nil {
		t.Fatal("expected the request to be rejected")
	}
}

func assertShapeError(t *testing.T, p *TransferParameters, want string) {
	t.Helper()
	err := p.ValidateShape()
	if err == nil {
		t.Fatalf("expected an error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func cloneFields(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}

// sampleTransferParams builds a shape-valid request for one variant. The
// ring-authority variant publishes neither co-signers nor output owner tags, so
// it carries one signer pk hash and no published owners.
func sampleTransferParams(variant Variant) *TransferParameters {
	const nInputs, nOutputs = 2, 2
	inputs := make([]InputParams, nInputs)
	for i := range inputs {
		inputs[i] = sampleInputParams(i)
	}
	outputs := make([]OutputParams, nOutputs)
	for i := range outputs {
		outputs[i] = OutputParams{
			Utxo:        sampleUtxoParams(),
			IsDummy:     big.NewInt(0),
			Hash:        big.NewInt(int64(0x900 + i)),
			OwnerPkHash: big.NewInt(0x1212),
			NullifierPk: big.NewInt(0x3333),
		}
	}
	signers := nInputs + 1
	publishedOwners := nOutputs
	if variant == RingAuthorityVariant {
		signers = 1
		publishedOwners = 0
	}
	return &TransferParameters{
		NInputs:                      nInputs,
		NOutputs:                     nOutputs,
		Inputs:                       inputs,
		Outputs:                      outputs,
		TreeSlots:                    sampleTreeSlots(),
		OutputTreeID:                 big.NewInt(7),
		ExternalDataHash:             big.NewInt(0x6666),
		PrivateTxHash:                big.NewInt(0x7777),
		BlindingSeed:                 big.NewInt(0x5EC1),
		PublicAssets:                 zeroFieldElements(txcircuit.NPublicSlots),
		PublicAmounts:                zeroFieldElements(txcircuit.NPublicSlots),
		RingProgramID:                big.NewInt(0x4242),
		SignerPkHashes:               countedFieldElements(signers, 0x1212),
		AllowDummyInputs:             big.NewInt(1),
		PublishedOutputOwnerPkHashes: countedFieldElements(publishedOwners, 0x1212),
		Variant:                      variant,
		PublicInputHash:              big.NewInt(0x8888),
	}
}

// sampleTreeSlots populates slots 0 and 1 and leaves the rest all zero, the
// unused-slot encoding no input may select.
func sampleTreeSlots() []common.TreeSlotParams {
	slots := make([]common.TreeSlotParams, txcircuit.InputTrees)
	for k := range slots {
		slots[k] = common.TreeSlotParams{
			ID:            big.NewInt(0),
			UtxoRoot:      big.NewInt(0),
			NullifierRoot: big.NewInt(0),
		}
	}
	slots[0] = common.TreeSlotParams{
		ID:            big.NewInt(7),
		UtxoRoot:      big.NewInt(11),
		NullifierRoot: big.NewInt(13),
	}
	slots[1] = common.TreeSlotParams{
		ID:            big.NewInt(8),
		UtxoRoot:      big.NewInt(17),
		NullifierRoot: big.NewInt(19),
	}
	return slots
}

// sampleInputParams spends input i from tree slot i, so the witness mapping is
// wrong-if-swapped rather than accidentally right.
func sampleInputParams(i int) InputParams {
	return InputParams{
		Utxo:                     sampleUtxoParams(),
		IsDummy:                  big.NewInt(0),
		StatePathElements:        zeroFieldElements(txcircuit.StateTreeHeight),
		StatePathIndex:           big.NewInt(0),
		NullifierLowValue:        big.NewInt(0),
		NullifierNextValue:       big.NewInt(0),
		NullifierLowPathElements: zeroFieldElements(txcircuit.NullifierTreeHeight),
		NullifierLowPathIndex:    big.NewInt(0),
		TreeSlot:                 big.NewInt(int64(i)),
		Nullifier:                big.NewInt(int64(100 + i)),
		OwnerPkHash:              big.NewInt(0x1212),
		NullifierSecret:          big.NewInt(0x4444),
	}
}

func sampleUtxoParams() UtxoParams {
	return UtxoParams{
		Domain:        big.NewInt(int64(txcircuit.UtxoDomain)),
		Owner:         big.NewInt(0x2121),
		Asset:         big.NewInt(1),
		Amount:        big.NewInt(5),
		Blinding:      big.NewInt(7),
		DataHash:      big.NewInt(0),
		RingDataHash:  big.NewInt(0),
		RingProgramID: big.NewInt(0x4242),
	}
}

func zeroFieldElements(n int) []*big.Int {
	return countedFieldElements(n, 0)
}

func countedFieldElements(n int, value int64) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(value)
	}
	return out
}
