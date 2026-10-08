package backend

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/logging"
	"zolana/prover/prover/timing"
)

type prover interface {
	Prove(constraint.ConstraintSystem, groth16.ProvingKey, witness.Witness) (groth16.Proof, error)
	Close() error
}

// ProveBatch returns proofs in witness order or one error for the whole batch.
type batchProver interface {
	prover
	ProveBatch(constraint.ConstraintSystem, groth16.ProvingKey, []witness.Witness) ([]groth16.Proof, error)
}

type cpuProver struct{}

func (cpuProver) Prove(ccs constraint.ConstraintSystem, key groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	return groth16.Prove(ccs, key, full)
}
func (cpuProver) Close() error { return nil }

// Options take effect only on a backend with ProveBatch.
type Options struct {
	BatchWindow time.Duration
	// BatchMax at one or zero proves every request alone.
	BatchMax int
}

const maxBatchWindow = time.Second

var state = struct {
	sync.RWMutex
	prover      prover
	batches     *batcher
	initialized bool
	gpu         bool
}{prover: cpuProver{}}

func Initialize(options Options) error {
	state.Lock()
	defer state.Unlock()
	if state.initialized {
		return fmt.Errorf("proof backend is already initialized")
	}
	state.prover, state.batches = nil, nil
	if options.BatchWindow < 0 || options.BatchWindow > maxBatchWindow || options.BatchMax < 0 {
		return fmt.Errorf("invalid proof batch window %s or size %d", options.BatchWindow, options.BatchMax)
	}
	name := os.Getenv("PROVER_BACKEND")
	if name == "" {
		name = defaultBackend
	}
	var selected prover = cpuProver{}
	var err error
	switch name {
	case "gnark":
	case "aeglos":
		selected, err = newGPU()
	case "aeglos-cpu":
		selected, err = newAeglosCPU()
	default:
		return fmt.Errorf("unknown proof backend %q", name)
	}
	if err != nil {
		return err
	}
	state.prover = selected
	if engine, ok := selected.(batchProver); ok && options.BatchMax > 1 {
		state.batches = newBatcher(engine, options)
	}
	state.initialized = true
	state.gpu = name == "aeglos"
	logging.Logger().Info().Str("proof_backend", name).Bool("batching", state.batches != nil).Msg("Proof backend initialized")
	return nil
}

// UsesGPU reports whether proofs, and so their inputs, reach a GPU.
func UsesGPU() bool {
	state.RLock()
	defer state.RUnlock()
	return state.gpu
}

func ProveAssignment(trace *timing.Trace, ccs constraint.ConstraintSystem, key groth16.ProvingKey, assign func() (frontend.Circuit, error)) (groth16.Proof, error) {
	finishWitness := trace.Start("witness")
	defer finishWitness()
	assignment, err := assign()
	if err != nil {
		return nil, err
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	finishWitness()
	proof, err := prove(trace, ccs, key, full)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return proof, nil
}

func prove(trace *timing.Trace, ccs constraint.ConstraintSystem, key groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	//1 - Backend ownership lasts until each admitted proof returns.
	state.RLock()
	defer state.RUnlock()
	if state.prover == nil {
		return nil, fmt.Errorf("proof backend is closed")
	}
	if state.batches != nil {
		return state.batches.prove(trace, ccs, key, full)
	}
	defer trace.Start("prove")()
	return state.prover.Prove(ccs, key, full)
}

func Close() error {
	state.Lock()
	defer state.Unlock()
	if state.prover == nil {
		return nil
	}
	err := state.prover.Close()
	state.prover, state.batches = nil, nil
	return err
}
