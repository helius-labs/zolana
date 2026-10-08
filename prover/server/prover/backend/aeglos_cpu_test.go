//go:build aeglos_cpu

package backend

import (
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	aeglos "github.com/helius-labs/aeglos"

	"zolana/prover/prover/timing"
)

func TestUnsetBackendIsAeglosCPU(t *testing.T) {
	resetBackend(t)
	t.Setenv("PROVER_BACKEND", "")
	t.Setenv("AEGLOS_CPU_THREADS", "2")
	t.Setenv("AEGLOS_CPU_FAMILY", "scalar")
	if err := Initialize(Options{BatchWindow: time.Millisecond, BatchMax: 4}); err != nil {
		t.Fatal(err)
	}
	engine, ok := state.prover.(*aeglos.Engine)
	if !ok || engine.Backend() != aeglos.BackendCPU {
		t.Fatal("Aeglos CPU backend was not selected")
	}
	if UsesGPU() || state.batches == nil {
		t.Fatal("Aeglos CPU backend claims a GPU or proves without batches")
	}
}

func TestAeglosCPURejectsInvalidSettings(t *testing.T) {
	for _, setting := range []struct{ name, value string }{
		{"AEGLOS_CPU_THREADS", "0"}, {"AEGLOS_CPU_THREADS", "-1"}, {"AEGLOS_CPU_THREADS", "all"},
		{"AEGLOS_CPU_FAMILY", "avx2"}, {"AEGLOS_MEMORY_LIMIT_BYTES", "0"},
		{"PROVER_BACKEND", "aeglos"},
	} {
		resetBackend(t)
		t.Setenv("PROVER_BACKEND", "aeglos-cpu")
		t.Setenv("AEGLOS_CPU_FAMILY", "scalar")
		t.Setenv(setting.name, setting.value)
		if err := Initialize(Options{}); err == nil {
			t.Fatalf("accepted %s=%q", setting.name, setting.value)
		}
	}
}

type chain struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

// Reaches the smallest domain Aeglos proves.
const chainLength = 1 << 14

func (c *chain) Define(api frontend.API) error {
	value := c.X
	for range chainLength {
		value = api.Mul(value, value)
	}
	api.AssertIsEqual(value, c.Y)
	return nil
}

type committedChain struct{ chain }

func (c *committedChain) Define(api frontend.API) error {
	commitment, err := api.(frontend.Committer).Commit(c.X)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	return c.chain.Define(api)
}

func chainAssignment(x int64) chain {
	exponent := new(big.Int).Lsh(big.NewInt(1), chainLength)
	return chain{X: x, Y: new(big.Int).Exp(big.NewInt(x), exponent, ecc.BN254.ScalarField())}
}

func TestAeglosCPUProofsVerify(t *testing.T) {
	resetBackend(t)
	t.Setenv("PROVER_BACKEND", "aeglos-cpu")
	if err := Initialize(Options{BatchWindow: maxBatchWindow, BatchMax: 3}); err != nil {
		t.Fatal(err)
	}
	for _, circuit := range []frontend.Circuit{&chain{}, &committedChain{}} {
		ccs := compile(t, circuit)
		key, verifyingKey, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatal(err)
		}
		var requests sync.WaitGroup
		for x := range int64(3) {
			requests.Go(func() {
				var assignment frontend.Circuit = new(chainAssignment(x + 2))
				if _, ok := circuit.(*committedChain); ok {
					assignment = &committedChain{chainAssignment(x + 2)}
				}
				trace := timing.New()
				proof, err := ProveAssignment(trace, ccs, key, func() (frontend.Circuit, error) { return assignment, nil })
				if err != nil {
					t.Error(err)
					return
				}
				for _, span := range trace.Snapshot() {
					if span.Name == "batch" && span.DurationMS >= float64(maxBatchWindow.Milliseconds()) {
						t.Error("request waited for the window instead of filling a batch")
					}
				}
				public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
				if err != nil {
					t.Error(err)
					return
				}
				if err := groth16.Verify(proof, verifyingKey, public); err != nil {
					t.Error(err)
				}
			})
		}
		requests.Wait()
	}
}
