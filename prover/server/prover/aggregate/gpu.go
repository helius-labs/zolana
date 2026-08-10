//go:build cuda

// Device-witness route for the aggregate prover. Builds witgen's DevicePK
// from the loaded proving system once per key and serves ProveAggregate
// requests from the GPU. witgen's device bridge is itself behind its
// cudawitgen tag, so this file compiles with -tags "cuda cudawitgen" on a
// machine with cuda/libwg.a and the ICICLE CUDA backend.
package aggregate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"zolana/prover/logging"
	"zolana/prover/prover/common"
	"zolana/prover/prover/gpuprove"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"

	"helios.local/witgen/bridge"
	"helios.local/witgen/exec"
	"helios.local/witgen/export"
)

// innerVKProvider supplies the per-slot inner verifying keys the pairing
// prep needs. Without it the prep is skipped and the pairing hints run
// synchronously inside the solve. The key manager owns the inner keys, so
// the wiring registers it at startup.
var innerVKProvider func(slots []common.AggregateSlot) ([]groth16.VerifyingKey, error)

// SetInnerVKProvider registers the inner verifying key source for the GPU
// prep path. Call before the first ProveAggregateBackend.
func SetInnerVKProvider(fn func(slots []common.AggregateSlot) ([]groth16.VerifyingKey, error)) {
	innerVKProvider = fn
}

// ProveAggregateBackend serves a batch on the GPU. PROVER_GPU=off forces the
// CPU prover and on errors without a usable device, the same contract as
// gpuprove. Key material that cannot reach the device falls back to the CPU
// prover once, at key load. A solve or assembly error is returned, never
// retried on the CPU. An invalid witness must fail the same way on both
// backends.
func ProveAggregateBackend(ps *common.AggregateProofSystem, legs []Leg) (*common.Proof, Backend, error) {
	if uint32(len(legs)) != ps.Batch() {
		return nil, BackendWitgenGPU, fmt.Errorf("%d legs against a batch of %d", len(legs), ps.Batch())
	}
	gpu, err := gpuprove.UseGPU()
	if err != nil {
		return nil, BackendWitgenGPU, err
	}
	if !gpu {
		proof, cpuErr := ProveAggregate(ps, legs)
		return proof, BackendGnarkCPU, cpuErr
	}
	prover, err := gpuProverFor(ps)
	if err != nil {
		logging.Logger().Warn().Err(err).Msg("witgen GPU prover unavailable, serving on gnark CPU")
		proof, cpuErr := ProveAggregate(ps, legs)
		return proof, BackendGnarkCPU, cpuErr
	}
	proof, err := prover.prove(legs)
	if err != nil {
		return nil, BackendWitgenGPU, err
	}
	return proof, BackendWitgenGPU, nil
}

// gpuProver is one key's resident device state. One tape upload and one
// DevicePK per proving system, reused for every request.
type gpuProver struct {
	mu   sync.Mutex // one resident witness per ctx, so proves serialize
	tape *exec.Tape
	ctx  *bridge.Ctx
	dpk  *bridge.DevicePK
	pp   *bridge.PairPrep // nil keeps the synchronous pairing hints
	nbIn int
}

// gpuCache keys by proving-system pointer. The lazy key manager caches one
// system per key for the process lifetime, so pointer identity is key
// identity. A failed build is cached too because a retry cannot succeed.
var (
	gpuMu    sync.Mutex
	gpuCache = map[*common.AggregateProofSystem]*gpuEntry{}
)

type gpuEntry struct {
	once   sync.Once
	prover *gpuProver
	err    error
}

func gpuProverFor(ps *common.AggregateProofSystem) (*gpuProver, error) {
	gpuMu.Lock()
	entry, ok := gpuCache[ps]
	if !ok {
		entry = &gpuEntry{}
		gpuCache[ps] = entry
	}
	gpuMu.Unlock()
	entry.once.Do(func() {
		start := time.Now()
		entry.prover, entry.err = newGPUProver(ps)
		if entry.err == nil {
			logging.Logger().Info().
				Dur("build", time.Since(start)).
				Str("key", ps.KeyName()).
				Msg("witgen DevicePK resident")
		}
	})
	return entry.prover, entry.err
}

func newGPUProver(ps *common.AggregateProofSystem) (*gpuProver, error) {
	r1cs, ok := ps.ConstraintSystem.(*cs_bn254.R1CS)
	if !ok {
		return nil, fmt.Errorf("constraint system is %T, want bn254 r1cs", ps.ConstraintSystem)
	}
	// Deserialized keys carry the icicle wrapper, witgen wants the embedded
	// stock key.
	pk, ok := gpuprove.StockProvingKey(ps.ProvingKey).(*groth16bn254.ProvingKey)
	if !ok {
		return nil, fmt.Errorf("proving key is %T, want bn254", ps.ProvingKey)
	}

	dir := os.Getenv("WG_TAPE_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	stem := filepath.Join(dir, strings.TrimSuffix(ps.KeyName(), ".key"))
	meta, err := export.Export(ps.ConstraintSystem, stem+".tape", stem+".meta.json")
	if err != nil {
		return nil, fmt.Errorf("export tape: %w", err)
	}
	tape, err := exec.Load(stem+".tape", exec.MetaSubset{
		NbWires:   meta.NbWires,
		NbPublic:  meta.NbPublic,
		NbSecret:  meta.NbSecret,
		HintKinds: meta.HintKinds,
	})
	if err != nil {
		return nil, fmt.Errorf("load tape: %w", err)
	}
	prep, err := bridge.Preprocess(tape)
	if err != nil {
		return nil, fmt.Errorf("preprocess: %w", err)
	}
	ctx, err := bridge.New(tape, prep)
	if err != nil {
		return nil, fmt.Errorf("device ctx: %w", err)
	}
	dpk, err := bridge.NewDevicePK(ctx, r1cs, pk, 0)
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("device pk: %w", err)
	}
	opts := bridge.StockProveOpts()
	// Precompute tables are setup work amortized over every request. These
	// defaults outperform the backend MSM defaults on every zolana key shape.
	// The WG_MSM_* env vars override each knob.
	if os.Getenv("WG_MSM_PRECOMPUTE") == "" {
		opts.Precompute = 4
	}
	if os.Getenv("WG_MSM_BUCKET") == "" {
		opts.BucketFactor = 5
	}
	if os.Getenv("WG_MSM_NCHUNKS") == "" {
		opts.NofChunks = 2
	}
	// The five assemble MSMs are mutually independent, so separate streams let
	// the device overlap them instead of running the chain serially. The a/b/c
	// transforms are contiguous in one buffer, so they run as batched NTT calls.
	opts.Streams = true
	opts.BatchNTT = true
	if err := dpk.SetOpts(opts); err != nil {
		dpk.Free()
		ctx.Close()
		return nil, fmt.Errorf("prove opts: %w", err)
	}
	g := &gpuProver{
		tape: tape,
		ctx:  ctx,
		dpk:  dpk,
		nbIn: meta.NbPublic + meta.NbSecret,
	}
	// Pairing prep moves the per-leg pairing hint off the solve's critical
	// path. It needs the inner verifying keys. Without a provider the solve
	// keeps the synchronous hint calls and stays correct.
	if innerVKProvider != nil {
		vks, err := innerVKProvider(ps.Slots)
		if err != nil {
			logging.Logger().Warn().Err(err).Msg("inner VKs unavailable, pairing prep off")
			return g, nil
		}
		pp, err := bridge.NewPairPrep(tape, prep, vks)
		if err != nil {
			logging.Logger().Warn().Err(err).Msg("pairing prep unavailable, synchronous hints")
			return g, nil
		}
		g.pp = pp
	}
	return g, nil
}

func (g *gpuProver) prove(legs []Leg) (*common.Proof, error) {
	full, err := legsWitness(legs)
	if err != nil {
		return nil, err
	}
	vec, ok := full.Vector().(fr.Vector)
	if !ok {
		return nil, fmt.Errorf("witness vector is %T, want bn254", full.Vector())
	}
	if len(vec)+1 != g.nbIn {
		return nil, fmt.Errorf("witness has %d wires, tape wants %d", len(vec)+1, g.nbIn)
	}
	inputs := make([]fr.Element, g.nbIn)
	inputs[0].SetOne()
	copy(inputs[1:], vec)

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pp != nil {
		// Recomputed per prove, the cached outputs are valid only for the
		// inputs they were computed from.
		if err := g.ctx.InstallPrepPairing(g.pp, inputs); err != nil {
			logging.Logger().Warn().Err(err).Msg("pairing prep skipped for this batch")
		}
	}
	proof, err := g.dpk.Prove(g.ctx, inputs, nil)
	if err != nil {
		return nil, fmt.Errorf("device prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}
