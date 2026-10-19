package policy

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func shapeKey(t *testing.T, shape common.RingPolicyShape) *common.RingProofSystem {
	t.Helper()
	path := filepath.Join("../../../proving-keys", common.RingKeyFile(shape.CircuitType()))
	if _, err := os.Stat(path); err != nil {
		t.Skipf("shape key not installed: %s", path)
	}
	loaded, err := common.ReadSystemFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ps, ok := loaded.(*common.RingProofSystem)
	if !ok {
		t.Fatalf("unexpected proof system %T", loaded)
	}
	return ps
}

// This exercises the files the serving prover loads, including both sparse and
// arbitrary-position authentication under every supported rail and capacity.
func TestShapedPoliciesInstalledKeys(t *testing.T) {
	for _, shape := range common.RingPolicyShapes {
		t.Run(string(shape.CircuitType()), func(t *testing.T) {
			ps := shapeKey(t, shape)
			w := shapeAssignment(t, shapeStatement(t, shape, shape.NInputs, shape.NOutputs), shape)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			public, err := witness.Public()
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
			if err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(start)
			if err = groth16.Verify(proof, ps.VerifyingKey, public); err != nil {
				t.Fatal(err)
			}
			t.Logf("constraints=%d proving=%s", ps.ConstraintSystem.GetNbConstraints(), elapsed)
		})
	}
}

func shapeRequest(w *ShapeCircuit, kind common.CircuitType) map[string]any {
	request := policyRequestJSON(reflect.ValueOf(w.Policy))
	for name, value := range policyRequestJSON(reflect.ValueOf(w.ShapeWires)) {
		request[name] = value
	}
	request["circuitType"] = string(kind)
	if w.Delegate {
		request = map[string]any{"circuitType": string(kind), "policy": request}
	}
	return request
}

// Freeze representative proofs for Rust's independent statement builder and
// pairing verifier. Full capacity coverage lives in the installed-key test.
func TestWriteShapeProofVectors(t *testing.T) {
	if os.Getenv("WRITE_RING_SHAPE_VECTORS") == "" {
		t.Skip("set WRITE_RING_SHAPE_VECTORS=1 to regenerate")
	}
	destination := "../../../../../custom-rings/sdk/tests/fixtures/shaped-proofs"
	if err := os.MkdirAll(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, shape := range common.RingPolicyShapes {
		selected := !shape.Anonymous && !shape.Delegate && ((shape.NInputs == 1 && shape.NOutputs == 2) || shape.NInputs == 16 || shape.NInputs == 24) || shape.Anonymous && (shape.NInputs == 3 || shape.NInputs == 12) || shape.Delegate && shape.NInputs == 4
		if !selected {
			continue
		}
		t.Run(string(shape.CircuitType()), func(t *testing.T) {
			ps := shapeKey(t, shape)
			w := shapeAssignment(t, shapeStatement(t, shape, shape.NInputs, shape.NOutputs), shape)
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			public, err := witness.Public()
			if err != nil {
				t.Fatal(err)
			}
			proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
			if err != nil {
				t.Fatal(err)
			}
			if err = groth16.Verify(proof, ps.VerifyingKey, public); err != nil {
				t.Fatal(err)
			}
			fields := []string{}
			for _, value := range public.Vector().(fr.Vector) {
				var n big.Int
				value.BigInt(&n)
				fields = append(fields, common.ToHex(&n))
			}
			vector := map[string]any{"request": shapeRequest(w, shape.CircuitType()), "publicInputs": fields, "proof": &common.Proof{Proof: proof, ProvingKeySha256: ps.ProvingKeySha256}}
			encoded, err := json.MarshalIndent(vector, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(destination, fmt.Sprintf("%s.json", shape.CircuitType()))
			if err = os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}
