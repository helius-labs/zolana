// Package benchprove backs the proving benchmarks in circuits/... with the
// production backend dispatch in prover/gpuprove, so a bench row measures
// the same prove path the server runs. Both backends load the pinned
// production proving systems through the same lazy key manager the server
// uses.
package benchprove

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"zolana/prover/prover/common"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Prove runs the production backend dispatch, see prover/gpuprove.
func Prove(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, fullWitness witness.Witness) (groth16.Proof, error) {
	return gpuprove.Prove(ccs, pk, fullWitness)
}

// Backend names the prove path for bench labels, "cpu" or "gpu".
func Backend() string {
	return gpuprove.Backend()
}

var (
	managerOnce sync.Once
	manager     *common.LazyKeyManager

	coldMu sync.Mutex
	// first-prove wall time per proving-system key. The pinned device state
	// survives across benchmark re-runs, so only the first call is cold.
	coldMs = map[string]float64{}
)

func keyManager(tb testing.TB) *common.LazyKeyManager {
	managerOnce.Do(func() {
		dir, err := keysDir()
		if err != nil {
			tb.Fatalf("locate proving-keys dir: %v", err)
		}
		manager = common.NewLazyKeyManager(dir, common.DefaultDownloadConfig())
	})
	return manager
}

// keysDir resolves SPP_KEYS_DIR, else walks up from the working directory to
// the module root and uses <root>/proving-keys.
func keysDir() (string, error) {
	if dir := os.Getenv("SPP_KEYS_DIR"); dir != "" {
		return dir, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "proving-keys"), nil
		}
		if filepath.Dir(dir) == dir {
			return "", fmt.Errorf("no go.mod above %s and SPP_KEYS_DIR unset", cwd)
		}
	}
}

// TransferSystem loads (downloading and caching on first use) the pinned
// proving system for one circuit type and shape. Benchmarks skip when the key
// cannot be loaded unless SPP_BENCH_REQUIRE_KEYS=1.
func TransferSystem(tb testing.TB, circuitType common.CircuitType, nInputs, nOutputs uint32) *common.TransferProofSystem {
	sys, err := keyManager(tb).GetTransferSystem(circuitType, nInputs, nOutputs)
	if err != nil {
		if os.Getenv("SPP_BENCH_REQUIRE_KEYS") == "1" {
			tb.Fatalf("load %s_%d_%d: %v", circuitType, nInputs, nOutputs, err)
		}
		tb.Skipf("proving key unavailable for %s_%d_%d: %v", circuitType, nInputs, nOutputs, err)
	}
	return sys
}

// RecordCold stores the first observed prove time for a system and returns the
// stored value on every later call, so re-runs of a benchmark report the true
// cold time instead of a warm re-measurement.
func RecordCold(systemKey string, elapsed time.Duration) float64 {
	coldMu.Lock()
	defer coldMu.Unlock()
	if v, ok := coldMs[systemKey]; ok {
		return v
	}
	v := float64(elapsed.Milliseconds())
	coldMs[systemKey] = v
	return v
}
