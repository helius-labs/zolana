package custom_ring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestShapedCircuitCatalog(t *testing.T) {
	if len(common.RingPolicyShapes) != 48 {
		t.Fatalf("got %d shaped keys", len(common.RingPolicyShapes))
	}
	counts := [3]int{}
	for _, shape := range common.RingPolicyShapes {
		if shape.NInputs > 16 || shape.NOutputs > 4 {
			t.Fatalf("oversized shape advertised: %v", shape)
		}
		rail := 0
		if shape.Anonymous {
			rail = 1
		}
		if shape.Delegate {
			rail = 2
		}
		counts[rail]++
		kind := shape.CircuitType()
		if _, err := Ring(kind); err != nil {
			t.Fatal(err)
		}
		if !kind.IsRing() || common.KeyFileCircuit(common.RingKeyFile(kind)) != kind {
			t.Fatalf("key catalog mismatch: %s", kind)
		}
	}
	if counts != [3]int{36, 8, 4} {
		t.Fatalf("unexpected rails %v", counts)
	}
	for _, name := range []string{"custom-ring-policy-1-8", "custom-ring-policy-24-2", "custom-ring-policy-49-2-subtree", "custom-ring-policy-1-2-anonymous", "custom-ring-delegate-policy-2-4"} {
		if common.CircuitType(name).IsRing() {
			t.Fatalf("unsupported circuit recognized: %s", name)
		}
	}
}

func TestShapedRustProofRequestsDecodeAndSolve(t *testing.T) {
	paths, err := filepath.Glob("../../../../custom-rings/sdk/tests/fixtures/shaped-proofs/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 10 {
		t.Fatalf("expected ten independent proof vectors, got %d", len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var vector struct {
				Request json.RawMessage `json:"request"`
			}
			if err = json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			meta, err := common.ParseProofRequestMeta(vector.Request)
			if err != nil {
				t.Fatal(err)
			}
			w, err := Decode(meta.CircuitType, vector.Request)
			if err != nil {
				t.Fatal(err)
			}
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			cs := compileRing(t, meta.CircuitType)
			if err = cs.IsSolved(witness); err != nil {
				t.Fatal(err)
			}
			// Strict assignment rejects legacy-sized arrays and out-of-capacity counts.
			for _, bad := range []string{"short inputs", "short subjects", "count overflow", "wrong mode"} {
				var raw map[string]any
				if err = json.Unmarshal(vector.Request, &raw); err != nil {
					t.Fatal(err)
				}
				body := raw
				if nested, ok := raw["policy"].(map[string]any); ok {
					body = nested
				}
				switch bad {
				case "short inputs":
					body["inputs"] = body["inputs"].([]any)[:0]
				case "short subjects":
					body["subjects"] = body["subjects"].([]any)[:1]
				case "count overflow":
					body["nIn"] = 17
				case "wrong mode":
					body["anonymous"] = !strings.Contains(string(meta.CircuitType), "anonymous")
				}
				payload, err := json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = Decode(meta.CircuitType, payload); err == nil {
					t.Fatalf("accepted %s", bad)
				}
			}
		})
	}
}
