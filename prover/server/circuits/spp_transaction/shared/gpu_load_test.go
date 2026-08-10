package shared_test

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"zolana/prover/prover-test/spp/benchprove"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

type loadWorkload struct {
	name        string
	sys         *common.TransferProofSystem
	fullWitness witness.Witness
	public      witness.Witness
	commitments int
}

// TestProveLoadMixedShapes fires M concurrent mixed-shape proves through the
// production backend dispatch and verifies every proof against the pinned vk.
// A CPU-only build runs the stock prover concurrently. A cuda build
// with a CUDA device serializes the GPU section through the device worker.
// Gated behind PROVER_LOAD_TEST=1, the pinned keys download on first use.
// PROVER_LOAD_SHAPES (csv of ring_I_O and p256_I_O, default
// ring_2_2,ring_2_3,p256_2_3) picks the request mix and PROVER_LOAD_M (csv,
// default 1,4,16) the concurrency sweep.
func TestProveLoadMixedShapes(t *testing.T) {
	if os.Getenv("PROVER_LOAD_TEST") != "1" {
		t.Skip("set PROVER_LOAD_TEST=1 to run, loads the pinned proving keys")
	}
	t.Logf("backend: %s", gpuprove.Backend())

	var workloads []loadWorkload
	for _, token := range loadShapeTokens() {
		var kind string
		var in, out int
		if _, err := fmt.Sscanf(token, "ring_%d_%d", &in, &out); err == nil {
			kind = "ring"
		} else if _, err := fmt.Sscanf(token, "p256_%d_%d", &in, &out); err == nil {
			kind = "p256"
		} else {
			t.Fatalf("bad PROVER_LOAD_SHAPES token %q, want ring_I_O or p256_I_O", token)
		}
		shape := protocol.Shape{NInputs: in, NOutputs: out}
		if kind == "ring" {
			workloads = append(workloads, buildRingLoadWorkload(t, shape))
		} else {
			workloads = append(workloads, buildP256LoadWorkload(t, shape))
		}
	}

	for _, m := range loadConcurrencies(t) {
		t.Run(fmt.Sprintf("concurrency_%d", m), func(t *testing.T) {
			proofs := make([]groth16.Proof, m)
			errs := make([]error, m)
			latencies := make([]time.Duration, m)

			var wg sync.WaitGroup
			start := time.Now()
			for i := range m {
				wl := workloads[i%len(workloads)]
				wg.Add(1)
				go func() {
					defer wg.Done()
					t0 := time.Now()
					proofs[i], errs[i] = gpuprove.Prove(wl.sys.ConstraintSystem, wl.sys.ProvingKey, wl.fullWitness)
					latencies[i] = time.Since(t0)
				}()
			}
			wg.Wait()
			wall := time.Since(start)

			for i := range m {
				wl := workloads[i%len(workloads)]
				if errs[i] != nil {
					t.Fatalf("prove %d (%s): %v", i, wl.name, errs[i])
				}
				if err := groth16.Verify(proofs[i], wl.sys.VerifyingKey, wl.public); err != nil {
					t.Fatalf("verify %d (%s): %v", i, wl.name, err)
				}
				assertCommitmentShape(t, proofs[i], wl)
			}

			sorted := slices.Clone(latencies)
			slices.Sort(sorted)
			t.Logf("m=%d wall=%v throughput=%.2f proofs/s latency min=%v med=%v max=%v",
				m, wall.Round(time.Millisecond), float64(m)/wall.Seconds(),
				sorted[0].Round(time.Millisecond), sorted[m/2].Round(time.Millisecond),
				sorted[m-1].Round(time.Millisecond))
		})
	}
}

func loadShapeTokens() []string {
	v := os.Getenv("PROVER_LOAD_SHAPES")
	if v == "" {
		v = "ring_2_2,ring_2_3,p256_2_3"
	}
	return strings.Split(v, ",")
}

func loadConcurrencies(t *testing.T) []int {
	t.Helper()
	v := os.Getenv("PROVER_LOAD_M")
	if v == "" {
		return []int{1, 4, 16}
	}
	var ms []int
	for _, s := range strings.Split(v, ",") {
		var m int
		if _, err := fmt.Sscanf(s, "%d", &m); err != nil || m < 1 {
			t.Fatalf("bad PROVER_LOAD_M entry %q", s)
		}
		ms = append(ms, m)
	}
	return ms
}

func buildRingLoadWorkload(t *testing.T, shape protocol.Shape) loadWorkload {
	t.Helper()
	sys := benchprove.TransferSystem(t, common.TransferRingCircuitType, uint32(shape.NInputs), uint32(shape.NOutputs))
	assignment := buildCircuitAssignment(t, shape)
	refreshPublicInputHash(t, assignment)
	return finishLoadWorkload(t, fmt.Sprintf("ring_%d_%d", shape.NInputs, shape.NOutputs), sys, asCustomRingEddsaOnly(assignment), 0)
}

func buildP256LoadWorkload(t *testing.T, shape protocol.Shape) loadWorkload {
	t.Helper()
	sys := benchprove.TransferSystem(t, common.TransferP256RingCircuitType, uint32(shape.NInputs), uint32(shape.NOutputs))
	assignment := buildCircuitAssignment(t, shape)
	owner := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, owner)
	authorization := authorizeP256(t, assignment, owner, owner)
	return finishLoadWorkload(t, fmt.Sprintf("p256_ring_%d_%d", shape.NInputs, shape.NOutputs), sys, asCustomRingP256(assignment, authorization), 1)
}

func finishLoadWorkload(t *testing.T, name string, sys *common.TransferProofSystem, circuit frontend.Circuit, commitments int) loadWorkload {
	t.Helper()
	fullWitness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("%s: build witness: %v", name, err)
	}
	public, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatalf("%s: build public witness: %v", name, err)
	}
	return loadWorkload{name: name, sys: sys, fullWitness: fullWitness, public: public, commitments: commitments}
}

// assertCommitmentShape pins the proof-JSON invariant: eddsa proofs carry no
// proof_commitment, P256 proofs carry exactly one.
func assertCommitmentShape(t *testing.T, proof groth16.Proof, wl loadWorkload) {
	t.Helper()
	bn254Proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		t.Fatalf("%s: unexpected proof type %T", wl.name, proof)
	}
	if got := len(bn254Proof.Commitments); got != wl.commitments {
		t.Fatalf("%s: commitment count: got %d want %d", wl.name, got, wl.commitments)
	}
	encoded, err := json.Marshal(&common.Proof{Proof: proof})
	if err != nil {
		t.Fatalf("%s: marshal proof: %v", wl.name, err)
	}
	hasCommitment := strings.Contains(string(encoded), `"proof_commitment"`)
	if hasCommitment != (wl.commitments > 0) {
		t.Fatalf("%s: proof_commitment presence %v does not match commitments %d", wl.name, hasCommitment, wl.commitments)
	}
}
