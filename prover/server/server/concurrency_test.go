package server

import (
	"runtime"
	"testing"
)

// workerConcurrency sizes each worker from cores and memory on one formula.
// The heavy batch worker lands memory-bound, the light transfer worker
// core-bound.
func TestWorkerConcurrencyIsCoreAndMemoryBounded(t *testing.T) {
	cases := []struct {
		name        string
		proofGB     int
		numCPU      int
		availableGB int
		want        int
	}{
		{"batch is memory bound on a high core host", batchProofMemoryGB, 48, 64, 4},
		{"batch floors at one when memory is tight", batchProofMemoryGB, 48, 10, 1},
		{"transfer is core bound when memory is ample", transferProofMemoryGB, 48, 256, 48},
		{"transfer is memory bound when memory is scarce", transferProofMemoryGB, 48, 20, 10},
		{"unknown memory forces the minimum", batchProofMemoryGB, 48, 0, 1},
		{"clamped to the maximum", transferProofMemoryGB, 400, 4000, MaxConcurrencyPerWorker},
	}
	for _, c := range cases {
		if got := workerConcurrency(c.proofGB, c.numCPU, c.availableGB); got != c.want {
			t.Errorf("%s: workerConcurrency(%d, %d, %d) = %d, want %d",
				c.name, c.proofGB, c.numCPU, c.availableGB, got, c.want)
		}
	}
}

// A batch proof holds batchProofMemoryGB and cannot be interrupted, so the
// unconfigured batch worker must never schedule past the budget. The former
// cores-only default violated this on a high-core, modest-memory host.
func TestBatchConcurrencyNeverExceedsMemoryBudget(t *testing.T) {
	for _, numCPU := range []int{8, 24, 48, 96} {
		for _, availableGB := range []int{16, 32, 64, 128, 256} {
			n := workerConcurrency(batchProofMemoryGB, numCPU, availableGB)
			if n > MinConcurrencyPerWorker && n*batchProofMemoryGB > availableGB {
				t.Errorf("at %d cores and %d GB the batch worker scheduled %d proofs holding %d GB, over budget",
					numCPU, availableGB, n, n*batchProofMemoryGB)
			}
		}
	}
}

// PROVER_MAX_CONCURRENCY is an explicit operator override and bypasses sizing.
func TestBatchConcurrencyHonoursExplicitOverride(t *testing.T) {
	t.Setenv("PROVER_MAX_CONCURRENCY", "7")
	if got := getMaxConcurrency(); got != 7 {
		t.Errorf("getMaxConcurrency() = %d, want 7", got)
	}
}

// PROVER_TOTAL_MEMORY_GB sizes the batch worker from a declared budget when the
// host does not expose live memory.
func TestBatchConcurrencyFromDeclaredMemory(t *testing.T) {
	t.Setenv("PROVER_MAX_CONCURRENCY", "")
	t.Setenv("PROVER_TOTAL_MEMORY_GB", "124")
	// (124 - hostMemoryReserveGB) / batchProofMemoryGB, capped by cores.
	want := workerConcurrency(batchProofMemoryGB, runtime.NumCPU(), 124-hostMemoryReserveGB)
	if got := getMaxConcurrency(); got != want {
		t.Errorf("getMaxConcurrency() = %d, want %d", got, want)
	}
}
