package backend

import (
	"fmt"
	"os"
	"sync"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
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
	var selected prover = cpuProver{}
	switch name {
	case "", "gnark":
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
	return nil
}

func Prove(ccs constraint.ConstraintSystem, key groth16.ProvingKey, full witness.Witness) (groth16.Proof, error) {
	//1 - Backend ownership lasts until each admitted proof returns.
	state.RLock()
	defer state.RUnlock()
	if state.prover == nil {
		return nil, fmt.Errorf("proof backend is closed")
	}
	return state.prover.Prove(ccs, key, full)
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
