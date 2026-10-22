package custom_ring

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"

	"github.com/helius-labs/zolana/prover/server/prover-test/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

var compiled sync.Map

func compileRing(t *testing.T, circuit common.CircuitType) constraint.ConstraintSystem {
	t.Helper()
	if cs, ok := compiled.Load(circuit); ok {
		return cs.(constraint.ConstraintSystem)
	}
	cs, err := ringOf(t, circuit).R1CS()
	if err != nil {
		t.Fatal(err)
	}
	compiled.Store(circuit, cs)
	return cs
}

// Every ring key compiles at its pin with one public input and one BSB22 commitment over private wires.
func TestRingKeyCatalog(t *testing.T) {
	names := make([]string, len(RingCircuits))
	for i, ring := range RingCircuits {
		names[i] = strings.TrimSuffix(common.RingKeyFile(ring.Type), ".key")
	}
	if !slices.Equal(slices.Sorted(slices.Values(names)), slices.Sorted(maps.Keys(ringkey.Pinned))) {
		t.Fatalf("ring keys %v differ from the pinned set", names)
	}
	for i, ring := range RingCircuits {
		t.Run(names[i], func(t *testing.T) {
			t.Parallel()
			ringkey.RequirePinned(t, names[i], compileRing(t, ring.Type))
		})
	}
}

func TestRingKeysCarryTheCompiledCircuits(t *testing.T) {
	for _, ring := range RingCircuits {
		t.Run(string(ring.Type), func(t *testing.T) {
			loaded := loadRingSystem(t, ring.Type)
			var fromKey, fresh bytes.Buffer
			if _, err := loaded.ConstraintSystem.WriteTo(&fromKey); err != nil {
				t.Fatal(err)
			}
			if _, err := compileRing(t, ring.Type).WriteTo(&fresh); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fromKey.Bytes(), fresh.Bytes()) {
				t.Fatalf("%s does not carry the compiled circuit, rotate the keys", common.RingKeyFile(ring.Type))
			}
		})
	}
}

// Skips the test when the circuit's proving key is absent.
func loadRingSystem(t *testing.T, circuit common.CircuitType) *common.RingProofSystem {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "proving-keys", common.RingKeyFile(circuit))
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is not available", path)
	}
	loaded, err := common.ReadSystemFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	system, ok := loaded.(*common.RingProofSystem)
	if !ok {
		t.Fatalf("unexpected proof system %T", loaded)
	}
	return system
}

// A request names every value its circuit reads, an omitted one is never assigned zero.
func TestDecodeNamesEveryMissingValue(t *testing.T) {
	for _, ring := range RingCircuits {
		_, err := Decode(ring.Type, []byte(`{"circuitType":"`+string(ring.Type)+`"}`))
		if err == nil || !strings.Contains(err.Error(), "PublicInputHash: missing") {
			t.Errorf("%s: an empty request decoded: %v", ring.Type, err)
		}
	}
}

// Each case changes one value of an honest request.
func TestDecodeRejectsMalformedRequests(t *testing.T) {
	requests := hostRequests(t)
	packed, apply := common.CircuitType("custom-ring-audit-packed-2"), common.CircuitType("custom-ring-apply-records-16")
	output := func(m map[string]any) map[string]any { return m["outputs"].([]any)[0].(map[string]any) }
	write := func(m map[string]any) map[string]any { return m["writes"].([]any)[0].(map[string]any) }
	modulus := "0x" + ecc.BN254.ScalarField().Text(16)
	canonical := "not canonical lowercase 0x hex"
	for _, tc := range []struct {
		name    string
		circuit common.CircuitType
		tamper  func(map[string]any)
		want    string
	}{
		{"unknown field", packed, func(m map[string]any) { m["externalDataHash"] = m["seedOut"] }, `unknown field "externalDataHash"`},
		{"unknown nested field", packed, func(m map[string]any) { output(m)["owner"] = m["seedOut"] }, `unknown field "owner"`},
		{"field name in another case", packed, func(m map[string]any) { m["SeedOut"] = m["seedOut"]; delete(m, "seedOut") }, `unknown field "SeedOut"`},
		{"null count", packed, func(m map[string]any) { m["nOut"] = nil }, "nOut: null value"},
		{"missing field", packed, func(m map[string]any) { delete(m, "seedOut") }, "SeedOut: missing"},
		{"null field", packed, func(m map[string]any) { m["seedOut"] = nil }, "SeedOut: missing"},
		{"field at the modulus", packed, func(m map[string]any) { m["seedOut"] = modulus }, canonical},
		{"uppercase hex", packed, func(m map[string]any) { m["auditorPk"] = strings.ToUpper(m["auditorPk"].(string)) }, canonical},
		{"short field", packed, func(m map[string]any) { m["seedOut"] = "0x01" }, canonical},
		{"long salt", packed, func(m map[string]any) { m["salt"] = m["salt"].(string) + "00" }, "Salt: expected 16 values"},
		{"count as a string", packed, func(m map[string]any) { m["nOut"] = "2" }, "PackedAuditParams.nOut of type uint8"},
		{"count above a byte", packed, func(m map[string]any) { m["nOut"] = 256 }, "number 256"},
		{"an output past the capacity", packed, func(m map[string]any) { m["outputs"] = append(m["outputs"].([]any), output(m)) }, "Outputs: expected 2 values"},
		{"one owner key short", packed, func(m map[string]any) { m["ownerKeys"] = m["ownerKeys"].([]any)[:1] }, "OwnerKeys: expected 2 values"},
		{"a write past the capacity", apply, func(m map[string]any) { m["writes"] = append(m["writes"].([]any), write(m)) }, "Writes: expected 16 values"},
		{"a path one sibling short", apply, func(m map[string]any) { write(m)["path"] = write(m)["path"].([]any)[1:] }, "Writes[0].Slot.Siblings[9]: expected 3 values"},
		{"a path one sibling long", apply, func(m map[string]any) { write(m)["lowPath"] = append(write(m)["lowPath"].([]any), m["oldRoot"]) }, "Writes[0].Low.Siblings: expected 10 values"},
		{"lists as a string", apply, func(m map[string]any) { write(m)["oldLists"] = "1" }, "oldLists of type uint64"},
		{"exists as a number", apply, func(m map[string]any) { write(m)["exists"] = 1 }, "exists of type bool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(mustMarshal(t, requests[tc.circuit]), &raw); err != nil {
				t.Fatal(err)
			}
			tc.tamper(raw)
			if _, err := Decode(tc.circuit, mustMarshal(t, raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	if _, err := Decode(packed, append(mustMarshal(t, requests[packed]), []byte("{}")...)); err == nil {
		t.Fatal("trailing data decoded")
	}
	repeated := append([]byte(`{"seedOut":"0x`+strings.Repeat("00", 32)+`",`), mustMarshal(t, requests[packed])[1:]...)
	if _, err := Decode(packed, repeated); err == nil || !strings.Contains(err.Error(), `repeated field "seedOut"`) {
		t.Fatalf("a repeated field decoded: %v", err)
	}
	if _, err := Decode("custom-ring-audit-packed-4", mustMarshal(t, requests[packed])); err == nil {
		t.Fatal("a request for the 2-output key decoded on the 4-output key")
	}
}
