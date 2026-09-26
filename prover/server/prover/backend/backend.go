package backend

import (
	"fmt"
	"os"
	"sync"

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

type cpuProver struct{}

func (cpuProver) Prove(ccs constraint.ConstraintSystem, key groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	return groth16.Prove(ccs, key, full)
}
func (cpuProver) Close() error { return nil }

var state = struct {
	sync.RWMutex
	prover      prover
	initialized bool
}{prover: cpuProver{}}

func Initialize() error {
	state.Lock()
	defer state.Unlock()
	if state.initialized {
		return fmt.Errorf("proof backend is already initialized")
	}
	state.prover = nil
	name := os.Getenv("PROVER_BACKEND")
	if name == "" {
		name = defaultBackend
	}
	var selected prover = cpuProver{}
	switch name {
	case "gnark":
	case "aeglos":
		var err error
		selected, err = newGPU()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown proof backend %q", name)
	}
	state.prover = selected
	state.initialized = true
	logging.Logger().Info().Str("proof_backend", name).Msg("Proof backend initialized")
	return nil
}

func prove(ccs constraint.ConstraintSystem, key groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	//1 - Backend ownership lasts until each admitted proof returns.
	state.RLock()
	defer state.RUnlock()
	if state.prover == nil {
		return nil, fmt.Errorf("proof backend is closed")
	}
	return state.prover.Prove(ccs, key, full)
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
	defer trace.Start("prove")()
	proof, err := prove(ccs, key, full)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return proof, nil
}

func Close() error {
	state.Lock()
	defer state.Unlock()
	if state.prover == nil {
		return nil
	}
	err := state.prover.Close()
	state.prover = nil
	return err
}
