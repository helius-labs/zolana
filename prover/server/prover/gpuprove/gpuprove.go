// Package gpuprove selects the Groth16 prove backend at run time.
//
// PROVER_GPU=auto|on|off controls the choice. auto (the default) uses the
// GPU only when the binary is built with the cuda tag and a CUDA device
// answers, on requires the GPU and fails otherwise, off forces the CPU.
// The variable is read once per process.
package gpuprove

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"

	"zolana/prover/logging"
)

// Prove runs Groth16 on the selected backend. GPU proves for one device run
// one at a time through a worker goroutine, CPU proves keep the caller's
// concurrency. Every call draws fresh randomness inside the backend, so a
// proof is never cached or reused.
func Prove(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	gpu, err := UseGPU()
	if err != nil {
		return nil, err
	}
	if gpu {
		logBackend("gpu")
		return proveGPU(ccs, pk, w)
	}
	logBackend("cpu")
	return proveCPU(ccs, pk, w)
}

// ProveCPU runs Groth16 on the CPU regardless of mode and device. In a cuda
// build it unwraps the device key wrapper first, so callers that own their
// device scheduling can still prove deserialized keys on the CPU.
func ProveCPU(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	return proveCPU(ccs, pk, w)
}

// UseGPU reports whether the selected mode, the build, and the device allow
// GPU proving. PROVER_GPU=on without a usable device is an error.
func UseGPU() (bool, error) {
	m, err := selectedMode()
	if err != nil {
		return false, err
	}
	switch m {
	case gpuOff:
		return false, nil
	case gpuOn:
		if !gpuBuilt {
			return false, errors.New("PROVER_GPU=on but the binary was built without the cuda tag")
		}
		if !gpuAvailable() {
			return false, errors.New("PROVER_GPU=on but no CUDA device answered")
		}
		return true, nil
	default:
		return gpuBuilt && gpuAvailable(), nil
	}
}

// Backend reports the backend Prove will use, "gpu" or "cpu".
func Backend() string {
	if gpu, err := UseGPU(); err == nil && gpu {
		return "gpu"
	}
	return "cpu"
}

type gpuMode int

const (
	gpuAuto gpuMode = iota
	gpuOn
	gpuOff
)

var (
	modeOnce sync.Once
	mode     gpuMode
	modeErr  error
)

func selectedMode() (gpuMode, error) {
	modeOnce.Do(func() {
		switch v := os.Getenv("PROVER_GPU"); v {
		case "", "auto":
			mode = gpuAuto
		case "on":
			mode = gpuOn
		case "off":
			mode = gpuOff
		default:
			modeErr = fmt.Errorf("invalid PROVER_GPU=%q, want auto, on or off", v)
		}
	})
	return mode, modeErr
}

var logBackendOnce sync.Once

func logBackend(name string) {
	logBackendOnce.Do(func() {
		logging.Logger().Info().Str("backend", name).Msg("prove backend selected")
	})
}
