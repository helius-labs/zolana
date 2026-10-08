package merge

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover/common"
)

// defaultTestNInputs is the merge shape these parameter tests build. Every
// supported count shares one witness-assignment path, so one shape covers it;
// TestValidateShapeAcceptsEverySupportedCount pins the set itself.
const defaultTestNInputs = 24

var sharedRequestKeys = []string{
	"circuitType",
	"inputs",
	"output",
	"treeSlots",
	"outputTreeId",
	"mint",
	"ownerPkHash",
	"userNullifierPk",
	"userNullifierSecret",
	"externalDataHash",
	"privateTxHash",
	"publicInputHash",
	"allowDummyInputs",
	"outputRingDataHash",
	"ringProgramId",
}

var defaultRailOnlyKeys = []string{"viewingPk", "ephemeralSk"}

func TestMergeParametersJSONRoundTrip(t *testing.T) {
	for _, p := range []*MergeParameters{sampleParams(), sampleRingParams()} {
		t.Run(string(p.CircuitType), func(t *testing.T) {
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
			if got.CircuitType != p.CircuitType {
				t.Fatalf("circuit type: got %s want %s", got.CircuitType, p.CircuitType)
			}
			if got.Mint != p.Mint || got.ViewingPk != p.ViewingPk || got.EphemeralSk != p.EphemeralSk {
				t.Fatalf("byte fields mismatch: got mint %x viewingPk %x ephemeralSk %x", got.Mint, got.ViewingPk, got.EphemeralSk)
			}
			again, err := json.Marshal(&got)
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			if !bytes.Equal(again, data) {
				t.Fatalf("round trip changed the request:\n got %s\nwant %s", again, data)
			}
		})
	}
}

// TestMergeParametersJSONKeys pins the request schema the Rust client encodes:
// tree identity is published once per slot and selected privately per input, so
// the per-input roots must be gone, and no field carries the private tx
// blinding (the circuit derives it from UserNullifierSecret).
func TestMergeParametersJSONKeys(t *testing.T) {
	cases := []struct {
		params *MergeParameters
		keys   []string
	}{
		{sampleParams(), append(slices.Clone(sharedRequestKeys), defaultRailOnlyKeys...)},
		{sampleRingParams(), sharedRequestKeys},
	}
	for _, tc := range cases {
		t.Run(string(tc.params.CircuitType), func(t *testing.T) {
			fields := marshalFields(t, tc.params)
			got := slices.Sorted(maps.Keys(fields))
			want := slices.Sorted(slices.Values(tc.keys))
			if !slices.Equal(got, want) {
				t.Fatalf("top-level keys:\n got %v\nwant %v", got, want)
			}

			var slots []map[string]json.RawMessage
			if err := json.Unmarshal(fields["treeSlots"], &slots); err != nil {
				t.Fatalf("unmarshal tree slots: %v", err)
			}
			if len(slots) != transaction.InputTrees {
				t.Fatalf("tree slot count: got %d want %d", len(slots), transaction.InputTrees)
			}
			assertKeys(t, "treeSlots[0]", slots[0], []string{"id", "utxoRoot", "nullifierRoot"})

			var inputs []map[string]json.RawMessage
			if err := json.Unmarshal(fields["inputs"], &inputs); err != nil {
				t.Fatalf("unmarshal inputs: %v", err)
			}
			assertKeys(t, "inputs[0]", inputs[0], []string{
				"domain", "amount", "blinding", "ringDataHash",
				"statePathElements", "statePathIndex",
				"nullifierLowValue", "nullifierNextValue", "nullifierLowPathElements", "nullifierLowPathIndex",
				"treeSlot", "nullifier",
			})

			var output map[string]json.RawMessage
			if err := json.Unmarshal(fields["output"], &output); err != nil {
				t.Fatalf("unmarshal output: %v", err)
			}
			assertKeys(t, "output", output, []string{"ringDataHash", "hash"})
		})
	}
}

func TestMergeParametersByteFieldsAreLowercaseHex(t *testing.T) {
	p := sampleParams()
	fields := marshalFields(t, p)
	want := map[string][]byte{
		"mint":        p.Mint[:],
		"viewingPk":   p.ViewingPk[:],
		"ephemeralSk": p.EphemeralSk[:],
	}
	for key, value := range want {
		var got string
		if err := json.Unmarshal(fields[key], &got); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if got != hex.EncodeToString(value) {
			t.Fatalf("%s: got %q want %q", key, got, hex.EncodeToString(value))
		}
	}
}

func TestMergeParametersAcceptPrefixedHex(t *testing.T) {
	p := sampleParams()
	got, err := unmarshalMutated(t, p, func(fields map[string]any) {
		for _, key := range []string{"mint", "viewingPk", "ephemeralSk"} {
			fields[key] = "0x" + fields[key].(string)
		}
	})
	if err != nil {
		t.Fatalf("0x-prefixed byte fields rejected: %v", err)
	}
	if got.Mint != p.Mint || got.ViewingPk != p.ViewingPk || got.EphemeralSk != p.EphemeralSk {
		t.Fatal("0x-prefixed byte fields decoded to different values")
	}
}

func TestMergeParametersRejectInvalidEnvelopeKeys(t *testing.T) {
	offCurve := sampleParams().ViewingPk
	offCurve[64] ^= 1
	compressedPrefix := sampleParams().ViewingPk
	compressedPrefix[0] = 0x02

	cases := []struct {
		name   string
		params *MergeParameters
		mutate func(map[string]any)
		want   string
	}{
		{"default rail without viewingPk", sampleParams(), deleteKey("viewingPk"), "viewingPk is required"},
		{"default rail without ephemeralSk", sampleParams(), deleteKey("ephemeralSk"), "ephemeralSk is required"},
		{"viewingPk with prefix 0x02", sampleParams(), setKey("viewingPk", hex.EncodeToString(compressedPrefix[:])), "viewingPk is not an uncompressed P-256 point"},
		{"viewingPk off the curve", sampleParams(), setKey("viewingPk", hex.EncodeToString(offCurve[:])), "viewingPk is not an uncompressed P-256 point"},
		{"compressed viewingPk", sampleParams(), setKey("viewingPk", hex.EncodeToString(compressedPrefix[:33])), "viewingPk must be 65 bytes, got 33"},
		{"viewingPk not hex", sampleParams(), setKey("viewingPk", "zz"), "merge: viewingPk"},
		{"zero ephemeralSk", sampleParams(), setKey("ephemeralSk", strings.Repeat("00", 32)), "ephemeralSk must be non-zero"},
		{"short ephemeralSk", sampleParams(), setKey("ephemeralSk", "01"), "ephemeralSk must be 32 bytes, got 1"},
		{"ring rail with viewingPk", sampleRingParams(), setKey("viewingPk", hex.EncodeToString(sampleParams().ViewingPk[:])), "must be absent on the ring rail"},
		{"ring rail with ephemeralSk", sampleRingParams(), setKey("ephemeralSk", hex.EncodeToString(sampleParams().EphemeralSk[:])), "must be absent on the ring rail"},
		{"unknown circuit type", sampleParams(), setKey("circuitType", "transfer"), "unsupported circuit type"},
		{"short mint", sampleParams(), setKey("mint", "01"), "mint must be 32 bytes, got 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unmarshalMutated(t, tc.params, tc.mutate)
			if err == nil {
				t.Fatal("expected the request to be rejected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestMergeParametersRejectMissingUserNullifierSecret guards the required
// field. The secret seeds the private tx blinding, so defaulting an absent one
// to zero would hand it to an observer.
func TestMergeParametersRejectMissingUserNullifierSecret(t *testing.T) {
	if _, err := unmarshalMutated(t, sampleParams(), deleteKey("userNullifierSecret")); err == nil {
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
	for _, params := range []*MergeParameters{sampleParams(), sampleRingParams()} {
		t.Run(string(params.CircuitType), func(t *testing.T) {
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

func marshalFields(t *testing.T, p *MergeParameters) map[string]json.RawMessage {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	return fields
}

func assertKeys(t *testing.T, name string, fields map[string]json.RawMessage, keys []string) {
	t.Helper()
	got := slices.Sorted(maps.Keys(fields))
	want := slices.Sorted(slices.Values(keys))
	if !slices.Equal(got, want) {
		t.Fatalf("%s keys:\n got %v\nwant %v", name, got, want)
	}
}

func unmarshalMutated(t *testing.T, p *MergeParameters, mutate func(map[string]any)) (*MergeParameters, error) {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	mutate(fields)
	mutated, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var got MergeParameters
	return &got, json.Unmarshal(mutated, &got)
}

func deleteKey(key string) func(map[string]any) {
	return func(fields map[string]any) { delete(fields, key) }
}

func setKey(key, value string) func(map[string]any) {
	return func(fields map[string]any) { fields[key] = value }
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
	keys := hosttest.DefaultKeys()
	return &MergeParameters{
		CircuitType:         common.MergeCircuitType,
		Inputs:              inputs,
		Output:              OutputParams{RingDataHash: big.NewInt(0), Hash: big.NewInt(0x9999)},
		TreeSlots:           treeSlots,
		OutputTreeID:        big.NewInt(11),
		Mint:                [32]byte{0: 0xab, 31: 1},
		ViewingPk:           keys.RecipientUncompressed(),
		EphemeralSk:         keys.EphemeralScalar(),
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

func sampleRingParams() *MergeParameters {
	p := sampleParams()
	p.CircuitType = common.MergeRingCircuitType
	p.ViewingPk = [65]byte{}
	p.EphemeralSk = [32]byte{}
	p.Output.RingDataHash = big.NewInt(0x33)
	p.OutputRingDataHash = big.NewInt(0x33)
	p.RingProgramID = big.NewInt(71)
	return p
}

func zeros(n int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}
