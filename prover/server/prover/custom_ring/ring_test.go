package custom_ring

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

var compiled sync.Map

func compileRing(t *testing.T, circuit common.CircuitType) constraint.ConstraintSystem {
	t.Helper()
	if cs, ok := compiled.Load(circuit); ok {
		return cs.(constraint.ConstraintSystem)
	}
	ring, err := Ring(circuit)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ring.R1CS()
	if err != nil {
		t.Fatal(err)
	}
	compiled.Store(circuit, cs)
	return cs
}

// The on-chain verifier takes one BSB22 commitment over private wires only.
func TestRingCircuitsCarryOnePrivateCommitment(t *testing.T) {
	for _, ring := range RingCircuits {
		t.Run(string(ring.Type), func(t *testing.T) {
			cs := compileRing(t, ring.Type)
			info, ok := cs.GetCommitments().(constraint.Groth16Commitments)
			if !ok || len(info) != 1 {
				t.Fatalf("%d commitments, want one", len(info))
			}
			if len(info[0].PublicAndCommitmentCommitted) != 0 {
				t.Fatalf("commitment covers %d public wires", len(info[0].PublicAndCommitmentCommitted))
			}
			public := 2
			if _, ok := ring.Circuit().(*policy.PublicTableTwoByThreeCircuit); ok {
				public = 79
			}
			if cs.GetNbPublicVariables() != public {
				t.Fatalf("%d public variables, want %d", cs.GetNbPublicVariables(), public)
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

func TestAssignNamesEveryMissingValue(t *testing.T) {
	for _, ring := range RingCircuits {
		_, err := Assign(ring.Type, ring.params())
		if err == nil || !strings.Contains(err.Error(), "PublicInputHash: missing") {
			t.Fatalf("%s: zero request assigned: %v", ring.Type, err)
		}
	}
	err := assign(RingCircuits[0].Circuit(), &PolicyParams{})
	for _, name := range []string{"PrivateTxHash: missing", "TxViewingSk: expected 32 values", "Inputs: expected 5 values", "Limits: expected 8 values", "TreeSlots: expected 5 values"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%q is not reported in %v", name, err)
		}
	}
}

// The encoder writes back the bytes clients send, the indexer resends them.
func TestGoldenRequestsRoundTripByteForByte(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, file := range files {
		payload, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := common.ParseProofRequestMeta(payload)
		if err != nil {
			t.Fatal(err)
		}
		ring, err := Ring(meta.CircuitType)
		if err != nil {
			t.Fatal(err)
		}
		params := ring.params()
		if err := Unmarshal(payload, params); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, compact.Bytes()) {
			t.Errorf("%s re-encodes differently", filepath.Base(file))
		}
	}
}

func TestDecodeRejectsMalformedRequests(t *testing.T) {
	payload, err := os.ReadFile("testdata/custom-ring-policy-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	field := strings.Repeat("0", 63) + "1"
	slot := func(m map[string]any, key string, i int) map[string]any { return m[key].([]any)[i].(map[string]any) }
	tests := map[string]func(map[string]any){
		"unknown field":               func(m map[string]any) { m["externalDataHash"] = "0x" + field },
		"unknown nested field":        func(m map[string]any) { slot(m, "inputs", 0)["owner"] = "0x" + field },
		"unknown tree slot field":     func(m map[string]any) { slot(m, "treeSlots", 0)["root"] = "0x" + field },
		"ciphertext hash on an input": func(m map[string]any) { slot(m, "inputs", 0)["ctHash"] = slot(m, "outputs", 0)["ctHash"] },
		"missing field":               func(m map[string]any) { delete(m, "privateTxHash") },
		"null field":                  func(m map[string]any) { m["addressChain"] = nil },
		"short field":                 func(m map[string]any) { m["privateTxHash"] = "0x01" },
		"uppercase":                   func(m map[string]any) { m["auditorPk"] = strings.ToUpper(m["auditorPk"].(string)) },
		"missing prefix":              func(m map[string]any) { m["ephSk"] = strings.TrimPrefix(m["ephSk"].(string), "0x") },
		"non hex":                     func(m map[string]any) { m["ephSk"] = "0x" + strings.Repeat("zz", 32) },
		"field at the modulus":        func(m map[string]any) { m["publicInputHash"] = "0x" + ecc.BN254.ScalarField().Text(16) },
		"short scalar":                func(m map[string]any) { m["txViewingSk"] = "0x00" },
		"long auditor key":            func(m map[string]any) { m["auditorPk"] = m["auditorPk"].(string) + "00" },
		"count as a string":           func(m map[string]any) { m["nIn"] = "1" },
		"count above a byte":          func(m map[string]any) { m["nIn"] = 256 },
		"short inputs":                func(m map[string]any) { m["inputs"] = m["inputs"].([]any)[:1] },
		"long rules":                  func(m map[string]any) { m["ruleEnc"] = append(m["ruleEnc"].([]any), m["ruleEnc"].([]any)[0]) },
		"short rule":                  func(m map[string]any) { m["ruleEnc"].([]any)[0] = "0x00" },
		"short subjects":              func(m map[string]any) { m["subjects"] = m["subjects"].([]any)[:1] },
		"short subject path": func(m map[string]any) {
			subject := slot(m, "subjects", 0)
			subject["path"] = subject["path"].([]any)[1:]
		},
		"lists as a string":      func(m map[string]any) { slot(m, "subjects", 0)["lists"] = "1" },
		"present as a number":    func(m map[string]any) { slot(m, "subjects", 0)["present"] = 1 },
		"unknown subject field":  func(m map[string]any) { slot(m, "subjects", 0)["member"] = "0x" + field },
		"short foreign subjects": func(m map[string]any) { m["foreignSubjects"] = m["foreignSubjects"].([]any)[:1] },
		"no tree slots":          func(m map[string]any) { m["treeSlots"] = []any{} },
		"six tree slots":         func(m map[string]any) { m["treeSlots"] = append(m["treeSlots"].([]any), make([]any, 5)...) },
	}
	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatal(err)
			}
			tamper(raw)
			data, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(common.CustomRingPolicyCircuitType, data); err == nil {
				t.Fatal("malformed request decoded")
			}
		})
	}
	if _, err := Decode(common.CustomRingPolicyCircuitType, append(payload, []byte("{}")...)); err == nil {
		t.Fatal("trailing data decoded")
	}
}

func TestDecodeRejectsMalformedAnonymousRequests(t *testing.T) {
	payload, err := os.ReadFile("testdata/custom-ring-base-anonymous.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(map[string]any){
		"anonymous as a number":    func(m map[string]any) { m["anonymous"] = 1 },
		"short sender":             func(m map[string]any) { m["sender"] = m["sender"].(string)[:64] },
		"three recipients":         func(m map[string]any) { m["recipients"] = m["recipients"].([]any)[:3] },
		"untagged viewing key":     func(m map[string]any) { m["recipientViewingKeys"].([]any)[0] = "0x" + strings.Repeat("11", 32) },
		"unknown input field":      func(m map[string]any) { m["inputs"].([]any)[0].(map[string]any)["key"] = "0x00" },
		"five inputs":              func(m map[string]any) { m["inputs"] = append(m["inputs"].([]any), m["inputs"].([]any)[0]) },
		"short anonymous outputs":  func(m map[string]any) { m["anonymousOutputs"] = m["anonymousOutputs"].([]any)[:1] },
		"blinding above the field": func(m map[string]any) { m["privateTxBlinding"] = "0x" + ecc.BN254.ScalarField().Text(16) },
		"uppercase recipient": func(m map[string]any) {
			m["recipients"].([]any)[0] = strings.ToUpper(m["recipients"].([]any)[0].(string))
		},
		"input count above a byte":  func(m map[string]any) { m["nIn"] = 256 },
		"recipients as one string":  func(m map[string]any) { m["recipients"] = m["sender"] },
		"viewing keys as an object": func(m map[string]any) { m["recipientViewingKeys"] = map[string]any{} },
	}
	for name, tamper := range tests {
		t.Run(name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatal(err)
			}
			tamper(raw)
			data, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(common.CustomRingBaseCircuitType, data); err == nil {
				t.Fatal("malformed anonymous request decoded")
			}
		})
	}
}
