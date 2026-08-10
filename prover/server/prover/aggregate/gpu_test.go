//go:build cuda

// GPU gate for the aggregate route. The aggregate flow served by the
// device-witness prover must verify under gnark's native verifier, round-trip
// the server marshal path, and reject a corrupted leg exactly like the CPU
// prover. Build with -tags "cuda cudawitgen" and point ZOLANA_SPP_KEYS_DIR at
// the shipped keys.
package aggregate_test

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"zolana/prover/prover/aggregate"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"helios.local/witgen/zcircuit"
)

type outerPublic struct {
	AggregateInputHash frontend.Variable `gnark:",public"`
}

func (*outerPublic) Define(frontend.API) error { return nil }

func outerWitness(t *testing.T, hashes []*big.Int) frontend.Circuit {
	t.Helper()
	chain, err := aggregate.AggregateInputHash(hashes)
	if err != nil {
		t.Fatal(err)
	}
	return &outerPublic{AggregateInputHash: chain}
}

func loadFixture(t *testing.T, batch int) (*common.AggregateProofSystem, *zcircuit.Batch) {
	t.Helper()
	keys := zcircuit.KeysDir()
	outer, err := zcircuit.LoadOuter(keys, uint32(batch))
	if err != nil {
		t.Skipf("outer key unavailable: %v", err)
	}
	inner, err := zcircuit.LoadInner(keys)
	if err != nil {
		t.Skipf("inner key unavailable: %v", err)
	}
	// the uniform test batches verify every slot against the one inner key
	aggregate.SetInnerVKProvider(func(slots []common.AggregateSlot) ([]groth16.VerifyingKey, error) {
		vks := make([]groth16.VerifyingKey, len(slots))
		for i := range vks {
			vks[i] = inner.VerifyingKey
		}
		return vks, nil
	})
	b, err := zcircuit.BuildBatch(inner, batch, 0)
	if err != nil {
		t.Fatalf("build batch: %v", err)
	}
	return outer, b
}

func TestGPUAggregateVerifiesAndRoundTrips(t *testing.T) {
	for _, batch := range []int{2, 3} {
		t.Run(fmt.Sprintf("b%d", batch), func(t *testing.T) {
			testGPUAggregateVerifiesAndRoundTrips(t, batch)
		})
	}
}

func testGPUAggregateVerifiesAndRoundTrips(t *testing.T, batch int) {
	outer, b := loadFixture(t, batch)

	proof, backend, err := aggregate.ProveAggregateBackend(outer, b.Legs)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if backend != aggregate.BackendWitgenGPU {
		t.Fatalf("served by %s, want %s", backend, aggregate.BackendWitgenGPU)
	}

	public, err := frontend.NewWitness(outerWitness(t, b.Hashes), ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof.Proof, outer.VerifyingKey, public); err != nil {
		t.Fatalf("gpu proof rejected by the native verifier: %v", err)
	}

	// The server marshal path is the wire format. A proof that cannot
	// round-trip it never reaches a client.
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back common.Proof
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := groth16.Verify(back.Proof, outer.VerifyingKey, public); err != nil {
		t.Fatalf("round-tripped proof rejected: %v", err)
	}
}

// A corrupted leg must fail on the GPU exactly as on the CPU, with the same
// rejection and the same failing constraint when both report one.
func TestGPUAggregateRejectsACorruptedLeg(t *testing.T) {
	outer, b := loadFixture(t, 2)

	// Leg 0 keeps its public input but carries leg 1's proof, a valid proof
	// of the wrong statement.
	bad := make([]aggregate.Leg, len(b.Legs))
	copy(bad, b.Legs)
	bad[0].Proof = b.Legs[1].Proof

	_, backend, gpuErr := aggregate.ProveAggregateBackend(outer, bad)
	if backend != aggregate.BackendWitgenGPU {
		t.Fatalf("served by %s, want %s", backend, aggregate.BackendWitgenGPU)
	}
	if gpuErr == nil {
		t.Fatal("gpu prover accepted a corrupted leg")
	}
	_, cpuErr := aggregate.ProveAggregate(outer, bad)
	if cpuErr == nil {
		t.Fatal("cpu prover accepted a corrupted leg")
	}
	t.Logf("gpu rejection %v", gpuErr)
	t.Logf("cpu rejection %v", cpuErr)
	gpuID, gpuOK := constraintID(gpuErr.Error())
	cpuID, cpuOK := constraintID(cpuErr.Error())
	if gpuOK && cpuOK && gpuID != cpuID {
		t.Fatalf("failing constraint differs, gpu #%s cpu #%s", gpuID, cpuID)
	}
}

func constraintID(s string) (string, bool) {
	_, after, found := strings.Cut(s, "constraint #")
	if !found {
		return "", false
	}
	id, _, _ := strings.Cut(after, " ")
	return id, true
}
