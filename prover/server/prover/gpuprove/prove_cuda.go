//go:build cuda

package gpuprove

import (
	"fmt"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	icicle_groth16 "github.com/consensys/gnark/backend/accelerated/icicle/groth16"
	icicle_bn254 "github.com/consensys/gnark/backend/accelerated/icicle/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"

	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"

	"zolana/prover/logging"
)

const gpuBuilt = true

var (
	detectOnce sync.Once
	gpuOK      bool
)

// gpuAvailable loads the ICICLE backend and probes CUDA device 0 once.
// A failed probe downgrades to the CPU instead of the panic the gnark
// warm-up path raises on a broken install.
func gpuAvailable() bool {
	detectOnce.Do(func() {
		if err := icicle_runtime.LoadBackendFromEnvOrDefault(); err != icicle_runtime.Success {
			logging.Logger().Warn().Str("err", err.AsString()).Msg("ICICLE backend load failed, using cpu")
			return
		}
		device := icicle_runtime.CreateDevice(icicle.CUDA.String(), 0)
		gpuOK = icicle_runtime.IsDeviceAvailable(&device)
		if !gpuOK {
			logging.Logger().Warn().Msg("no CUDA device answered, using cpu")
		}
	})
	return gpuOK
}

type gpuJob struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	w   witness.Witness
	res chan gpuResult
}

type gpuResult struct {
	proof groth16.Proof
	err   error
}

var (
	workerOnce sync.Once
	gpuJobs    chan gpuJob
)

// proveGPU serializes whole icicle Prove calls through one worker goroutine
// for device 0. The icicle backend holds one NTT domain per device, and its
// Prove runs the CPU witness solve internally, so the solve rides inside the
// serialized section. At most one prove is in flight on the device per
// process.
func proveGPU(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	// A stock key reaches this path only from an in-process groth16.Setup,
	// keys deserialized through NewProvingKey carry the wrapper. The gnark
	// dispatcher would panic on the assert, prove on the CPU instead.
	if _, ok := pk.(*icicle_bn254.ProvingKey); !ok {
		logging.Logger().Warn().Msg("proving key lacks icicle device state, proving on cpu")
		return proveCPU(ccs, pk, w)
	}
	workerOnce.Do(func() {
		gpuJobs = make(chan gpuJob)
		go gpuWorkerLoop()
	})
	res := make(chan gpuResult, 1)
	gpuJobs <- gpuJob{ccs: ccs, pk: pk, w: w, res: res}
	r := <-res
	return r.proof, r.err
}

// gpuWorkerLoop keeps a reader on gpuJobs for the life of the process. gpuJobs
// is never closed and has no buffer, so a worker that stops leaves every later
// send blocked forever.
func gpuWorkerLoop() {
	for {
		gpuWorker()
		logging.Logger().Error().Msg("gpu worker stopped, restarting it")
	}
}

func gpuWorker() {
	// Backstop for a panic outside a job. The loop can only put a reader back
	// on gpuJobs if this frame returns instead of unwinding the process.
	defer func() {
		if r := recover(); r != nil {
			logging.Logger().Error().Interface("panic", r).Msg("gpu worker panicked")
		}
	}()

	opts := []icicle.Option{icicle.WithDeviceID(0)}
	// Pinning keeps every loaded proving key resident in GPU memory. Off by
	// default, the full pinned key set can exceed device memory.
	if os.Getenv("PROVER_GPU_PIN_KEYS") == "1" {
		opts = append(opts, icicle.WithPinKeysToGPU(true))
	}
	for job := range gpuJobs {
		job.res <- proveOnDevice(job, opts)
	}
}

// proveOnDevice turns a panic in the icicle prover, which a malformed witness
// or a device out of memory raises, into a result. An escaping panic would
// leave the caller blocked on its result channel with no worker to answer it.
func proveOnDevice(job gpuJob, opts []icicle.Option) (result gpuResult) {
	defer func() {
		if r := recover(); r != nil {
			logging.Logger().Error().Interface("panic", r).Msg("gpu prove panicked")
			result = gpuResult{err: fmt.Errorf("gpu prove panicked: %v", r)}
		}
	}()
	proof, err := icicle_groth16.Prove(job.ccs, job.pk, job.w, opts...)
	return gpuResult{proof: proof, err: err}
}

// proveCPU unwraps the icicle key wrapper, the stock dispatcher type-asserts
// the exact bn254 key type and would panic on the wrapper.
func proveCPU(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	if icPk, ok := pk.(*icicle_bn254.ProvingKey); ok {
		if r1cs, ok := ccs.(*cs_bn254.R1CS); ok {
			proof, err := groth16_bn254.Prove(r1cs, &icPk.ProvingKey, w)
			if err != nil {
				return nil, err
			}
			return proof, nil
		}
	}
	return groth16.Prove(ccs, pk, w)
}

// NewProvingKey allocates the icicle wrapper so device state can attach to
// the cached key object. The wrapper embeds the stock key, serialization and
// the CPU fallback read the same bytes.
func NewProvingKey() groth16.ProvingKey {
	return icicle_groth16.NewProvingKey(ecc.BN254)
}

// StockProvingKey returns the embedded stock bn254 key of a wrapper key, or
// the key itself when it is already stock. Callers that hand the key to a
// non-gnark backend need the exact bn254 type.
func StockProvingKey(pk groth16.ProvingKey) groth16.ProvingKey {
	if icPk, ok := pk.(*icicle_bn254.ProvingKey); ok {
		return &icPk.ProvingKey
	}
	return pk
}
