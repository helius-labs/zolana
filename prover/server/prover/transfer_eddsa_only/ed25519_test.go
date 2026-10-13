package transfereddsaonly

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	customring "zolana/prover/circuits/spp_transaction/custom"
	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

// TestEd25519TransferParametersJSONRoundTrip pins the Ed25519 rail's request
// schema and the fields the decoder must refuse. The Ed25519 request reuses the
// Solana-only encoder, so it must carry the same tree slots and single blinding
// seed and none of the per-input roots or pre-derived blindings.
func TestEd25519TransferParametersJSONRoundTrip(t *testing.T) {
	params := sampleEd25519Params()

	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	var circuitType string
	if err := json.Unmarshal(raw["circuitType"], &circuitType); err != nil {
		t.Fatalf("unmarshal circuit type: %v", err)
	}
	if circuitType != string(common.TransferP256RingCircuitType) {
		t.Fatalf("circuit type = %v", circuitType)
	}
	for _, key := range []string{"treeSlots", "outputTreeId", "blindingSeed"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing top-level key %q in %s", key, encoded)
		}
	}
	for _, key := range []string{"outputBlindingSeed", "privateTxBlinding", "p256SigningPkField"} {
		if _, ok := raw[key]; ok {
			t.Fatalf("obsolete key %q must not be serialized", key)
		}
	}

	var slots []map[string]json.RawMessage
	if err := json.Unmarshal(raw["treeSlots"], &slots); err != nil {
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
	if err := json.Unmarshal(raw["inputs"], &inputs); err != nil {
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

	var decoded Ed25519TransferParameters
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if decoded.NInputs != 1 || decoded.NOutputs != 1 {
		t.Fatalf("shape = %dx%d", decoded.NInputs, decoded.NOutputs)
	}
	if decoded.OutputTreeID.Cmp(params.OutputTreeID) != 0 {
		t.Fatalf("output tree id = %v", decoded.OutputTreeID)
	}
	if decoded.BlindingSeed.Cmp(params.BlindingSeed) != 0 {
		t.Fatalf("blinding seed = %v", decoded.BlindingSeed)
	}
	if decoded.Inputs[0].TreeSlot.Cmp(params.Inputs[0].TreeSlot) != 0 {
		t.Fatalf("input tree slot = %v", decoded.Inputs[0].TreeSlot)
	}
	for k := range params.TreeSlots {
		have, want := decoded.TreeSlots[k], params.TreeSlots[k]
		if have.ID.Cmp(want.ID) != 0 ||
			have.UtxoRoot.Cmp(want.UtxoRoot) != 0 ||
			have.NullifierRoot.Cmp(want.NullifierRoot) != 0 {
			t.Fatalf("tree slot %d: got %v want %v", k, have, want)
		}
	}
	if err := decoded.ValidateShape(); err != nil {
		t.Fatalf("validate shape: %v", err)
	}
}

// TestEd25519TransferParametersRejectBlindingSeed guards the transaction's single
// private random value: the circuit derives the private tx blinding and every
// output blinding from it, so a zero or omitted seed hands an observer both
// and must be refused at parse time.
func TestEd25519TransferParametersRejectBlindingSeed(t *testing.T) {
	encoded, err := json.Marshal(sampleEd25519Params())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	t.Run("omitted", func(t *testing.T) {
		stripped := cloneFields(fields)
		delete(stripped, "blindingSeed")
		assertEd25519DecodeFails(t, stripped)
	})

	t.Run("zero", func(t *testing.T) {
		zeroed := cloneFields(fields)
		zeroed["blindingSeed"] = "0x0"
		assertEd25519DecodeFails(t, zeroed)
	})
}

func assertEd25519DecodeFails(t *testing.T, fields map[string]any) {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var got Ed25519TransferParameters
	if err := json.Unmarshal(data, &got); err == nil {
		t.Fatal("expected the request to be rejected")
	}
}

// sampleEd25519Params spends its single input from tree slot 0; slots 1..4 stay
// all zero, the unused-slot encoding no input may select.
func sampleEd25519Params() *Ed25519TransferParameters {
	zero := big.NewInt(0)
	treeSlots := make([]common.TreeSlotParams, txcircuit.InputTrees)
	for k := range treeSlots {
		treeSlots[k] = common.TreeSlotParams{ID: zero, UtxoRoot: zero, NullifierRoot: zero}
	}
	treeSlots[0] = common.TreeSlotParams{
		ID:            big.NewInt(7),
		UtxoRoot:      big.NewInt(11),
		NullifierRoot: big.NewInt(13),
	}
	input := sampleInputParams(0)
	return &Ed25519TransferParameters{
		NInputs:  1,
		NOutputs: 1,
		Inputs:   []InputParams{input},
		Outputs: []OutputParams{{
			Utxo:        sampleUtxoParams(),
			IsDummy:     zero,
			Hash:        big.NewInt(0x900),
			OwnerPkHash: big.NewInt(0x1212),
			NullifierPk: big.NewInt(0x3333),
		}},
		TreeSlots:                    treeSlots,
		OutputTreeID:                 big.NewInt(7),
		ExternalDataHash:             big.NewInt(0x6666),
		PrivateTxHash:                big.NewInt(0x7777),
		BlindingSeed:                 big.NewInt(0x5EC1),
		Ed25519PublicKey:             sampleBytes32(0x10),
		Ed25519Signature:             sampleBytes64(0x40),
		Ed25519MessageHashLow:        big.NewInt(0x1001),
		Ed25519MessageHashHigh:       big.NewInt(0x2002),
		DefaultEd25519OwnerPkHash:    zero,
		PublicAssets:                 zeroFieldElements(txcircuit.NPublicSlots),
		PublicAmounts:                zeroFieldElements(txcircuit.NPublicSlots),
		RingProgramID:                big.NewInt(0x4242),
		SignerPkHashes:               countedFieldElements(2, 0x1212),
		InputFlags:                   sampleInputFlags([]InputParams{input}),
		PublishedOutputOwnerPkHashes: countedFieldElements(1, 0x1212),
		PublicInputHash:              big.NewInt(0x8888),
	}
}

func sampleBytes32(start byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func sampleBytes64(start byte) [64]byte {
	var out [64]byte
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

// TestEd25519TransferParametersKeyAndSignatureEncoding pins the byte fields of
// the request: 0x-prefixed lowercase hex of exactly 32 and 64 bytes, decoded
// in order into the circuit's byte inputs.
func TestEd25519TransferParametersKeyAndSignatureEncoding(t *testing.T) {
	params := sampleEd25519Params()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if got, want := fields["ed25519PublicKey"], "0x"+hex.EncodeToString(params.Ed25519PublicKey[:]); got != want {
		t.Fatalf("ed25519PublicKey = %v, want %v", got, want)
	}
	if got, want := fields["ed25519Signature"], "0x"+hex.EncodeToString(params.Ed25519Signature[:]); got != want {
		t.Fatalf("ed25519Signature = %v, want %v", got, want)
	}
	for _, key := range []string{"ed25519MessageHashLow", "ed25519MessageHashHigh", "defaultEd25519OwnerPkHash"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing key %q", key)
		}
	}
	for _, key := range []string{"p256PubX", "p256PubY", "p256SigR", "p256SigS", "p256MessageHashLow", "p256MessageHashHigh", "defaultP256OwnerPkHash"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("obsolete key %q must not be serialized", key)
		}
	}

	var decoded Ed25519TransferParameters
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if decoded.Ed25519PublicKey != params.Ed25519PublicKey || decoded.Ed25519Signature != params.Ed25519Signature {
		t.Fatal("key or signature bytes changed in the round trip")
	}

	for name, value := range map[string]string{
		"short key":      "0x" + hex.EncodeToString(params.Ed25519PublicKey[:31]),
		"missing prefix": hex.EncodeToString(params.Ed25519PublicKey[:]) + "00",
		"uppercase hex":  "0x" + strings.ToUpper(hex.EncodeToString(params.Ed25519PublicKey[:])),
		"field element":  "0x10",
		"empty":          "",
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneFields(fields)
			changed["ed25519PublicKey"] = value
			assertEd25519DecodeFails(t, changed)
		})
	}

	circuit, err := decoded.CreateWitness()
	if err != nil {
		t.Fatalf("create witness: %v", err)
	}
	private := circuit.(*customring.CustomRingEd25519Circuit).Private
	for i, b := range params.Ed25519PublicKey {
		if private.Ed25519PublicKey[i] != b {
			t.Fatalf("public key byte %d = %v, want %d", i, private.Ed25519PublicKey[i], b)
		}
	}
	for i, b := range params.Ed25519Signature {
		if private.Ed25519Signature[i] != b {
			t.Fatalf("signature byte %d = %v, want %d", i, private.Ed25519Signature[i], b)
		}
	}
}
