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

var pinnedRingConstraints = map[string]int{
	"custom_ring_audit_packed_2":            53425,
	"custom_ring_audit_packed_4":            64748,
	"custom_ring_audit_delivered_8":         283971,
	"custom_ring_audit_delivered_16":        523700,
	"custom_ring_audit_anonymous_4_2":       124338,
	"custom_ring_audit_anonymous_8_2":       131915,
	"custom_ring_audit_anonymous_12_2":      139495,
	"custom_ring_audit_anonymous_16_2":      147078,
	"custom_ring_audit_anonymous_24_2":      162235,
	"custom_ring_audit_anonymous_28_2":      169818,
	"custom_ring_audit_anonymous_4_4":       186134,
	"custom_ring_audit_anonymous_8_4":       193711,
	"custom_ring_audit_anonymous_12_4":      201291,
	"custom_ring_audit_anonymous_16_4":      208874,
	"custom_ring_audit_anonymous_24_4":      224031,
	"custom_ring_audit_anonymous_4_8":       311457,
	"custom_ring_audit_anonymous_8_8":       319034,
	"custom_ring_audit_anonymous_12_8":      326614,
	"custom_ring_audit_anonymous_16_8":      334197,
	"custom_ring_audit_anonymous_entry_8_2": 138013,
	"custom_ring_audit_anonymous_entry_8_4": 199809,
	"custom_ring_audit_anonymous_entry_8_8": 325132,
	"custom_ring_policy_member_2":           48455,
	"custom_ring_policy_member_4":           82348,
	"custom_ring_policy_member_8":           150253,
	"custom_ring_policy_member_16":          286047,
	"custom_ring_policy_delegate_1x2":       48736,
	"custom_ring_policy_delegate_1x4":       82565,
	"custom_ring_policy_delegate_1x8":       150391,
	"custom_ring_policy_delegate_2x2":       50089,
	"custom_ring_policy_delegate_2x4":       83918,
	"custom_ring_policy_delegate_1x16":      285928,
	"custom_ring_policy_delegate_2x8":       151744,
	"custom_ring_policy_delegate_3x2":       51442,
	"custom_ring_policy_delegate_3x4":       85271,
	"custom_ring_policy_delegate_2x16":      287281,
	"custom_ring_policy_delegate_3x8":       153097,
	"custom_ring_policy_delegate_4x2":       52795,
	"custom_ring_policy_delegate_4x4":       86624,
	"custom_ring_policy_delegate_4x8":       154450,
	"custom_ring_policy_delegate_5x2":       54148,
	"custom_ring_policy_delegate_5x4":       87977,
	"custom_ring_policy_delegate_4x16":      289987,
	"custom_ring_policy_delegate_5x8":       155803,
	"custom_ring_policy_delegate_6x2":       55501,
	"custom_ring_policy_delegate_6x4":       89330,
	"custom_ring_policy_delegate_5x16":      291340,
	"custom_ring_policy_delegate_6x8":       157156,
	"custom_ring_policy_delegate_8x2":       58207,
	"custom_ring_policy_delegate_8x4":       92036,
	"custom_ring_policy_delegate_8x8":       159862,
	"custom_ring_policy_delegate_8x16":      295399,
	"custom_ring_policy_delegate_12x2":      63619,
	"custom_ring_policy_delegate_12x4":      97448,
	"custom_ring_policy_delegate_12x8":      165274,
	"custom_ring_policy_delegate_16x2":      69031,
	"custom_ring_policy_delegate_16x4":      102860,
	"custom_ring_policy_delegate_16x8":      170686,
	"custom_ring_policy_delegate_24x2":      79855,
	"custom_ring_policy_delegate_24x4":      113684,
	"custom_ring_policy_delegate_32x2":      90679,
	"custom_ring_policy_delegate_40x2":      101503,
	"custom_ring_apply_records_1":           15492,
	"custom_ring_apply_records_16":          232892,
	"custom_ring_register_key":              36913,
	"custom_ring_deposit":                   148856,
	"custom_ring_merge_anonymous_8":         56112,
	"custom_ring_merge_anonymous_24":        81618,
}

// Every ring key compiles at its pin with one public input and one BSB22 commitment over private wires.
func TestRingKeyCatalog(t *testing.T) {
	names := make([]string, len(RingCircuits))
	for i, ring := range RingCircuits {
		names[i] = strings.TrimSuffix(common.RingKeyFile(ring.Type), ".key")
	}
	if !slices.Equal(slices.Sorted(slices.Values(names)), slices.Sorted(maps.Keys(pinnedRingConstraints))) {
		t.Fatalf("ring keys %v differ from the pinned set", names)
	}
	for i, ring := range RingCircuits {
		t.Run(names[i], func(t *testing.T) {
			t.Parallel()
			cs := compileRing(t, ring.Type)
			if got, want := cs.GetNbConstraints(), pinnedRingConstraints[names[i]]; got != want {
				t.Errorf("%d constraints, pinned %d", got, want)
			}
			if public := cs.GetNbPublicVariables() - 1; public != 1 {
				t.Errorf("%d public inputs, the program verifies one", public)
			}
			commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
			if !ok || len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 {
				t.Errorf("commitments %v, want one over private wires", cs.GetCommitments())
			}
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
	if _, err := Decode("custom-ring-audit-packed-4", mustMarshal(t, requests[packed])); err == nil {
		t.Fatal("a request for the 2-output key decoded on the 4-output key")
	}
}
