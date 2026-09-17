package directspend_test

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	direct "zolana/prover/circuits/direct_spend"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/common"
)

// freshness builds a non-membership witness for n fresh nullifiers against a
// nullifier tree holding 64 historical entries, the same fixture shape the
// scattered payment uses.
func freshness(t *testing.T, n int) *direct.GKRFreshnessCircuit {
	t.Helper()
	w := direct.NewGKRFreshness(n)
	nfs, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 64 {
		if err := nfs.Insert(hash(t, 991, i)); err != nil {
			t.Fatal(err)
		}
	}
	w.TreeID, w.Root, w.Count = 7, nfs.Root(), n
	for i := range n {
		nullifier := hash(t, 7, i)
		witness, err := nfs.NonInclusionWitness(nullifier)
		if err != nil {
			t.Fatal(err)
		}
		w.Nullifiers[i] = nullifier
		w.Witnesses[i] = direct.NonInclusion{
			Low: witness.LowValue, Next: witness.NextValue, Index: witness.LowIndex, Path: variables(witness.PathElements),
		}
	}
	bindFreshness(t, w)
	return w
}

func bindFreshness(t *testing.T, w *direct.GKRFreshnessCircuit) {
	t.Helper()
	w.PublicInputHash = chain(t, freshnessFields(t, w.Freshness))
}

func TestGKRFreshness(t *testing.T) {
	// The GKR variant must accept exactly the FreshnessCircuit witnesses,
	// padded or full.
	padded := payment(t, 4, 2)
	full := freshness(t, 4)
	for _, w := range []*direct.GKRFreshnessCircuit{
		{Freshness: padded.Freshness, PublicInputHash: chain(t, freshnessFields(t, padded.Freshness))},
		full,
	} {
		if err := test.IsSolved(direct.NewGKRFreshness(4), w, ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGKRFreshnessRejects(t *testing.T) {
	cases := map[string]func(*direct.GKRFreshnessCircuit){
		"spent nullifier": func(w *direct.GKRFreshnessCircuit) { w.Witnesses[1].Low = w.Nullifiers[1] },
		"wrong root":      func(w *direct.GKRFreshnessCircuit) { w.Root = 1 },
		"wrong path":      func(w *direct.GKRFreshnessCircuit) { w.Witnesses[2].Path[13] = 1 },
		"wrong index":     func(w *direct.GKRFreshnessCircuit) { w.Witnesses[2].Index = 5 },
		"substitution":    func(w *direct.GKRFreshnessCircuit) { w.Nullifiers[0] = 1 },
		"wrong count":     func(w *direct.GKRFreshnessCircuit) { w.Count = 3 },
		// TreeID is only range-checked and bound into the statement; the program
		// ties it to the root, so it is not a circuit-level rejection.
		"out of range": func(w *direct.GKRFreshnessCircuit) {
			w.Witnesses[3].Next = new(big.Int).Sub(integers(t, []frontend.Variable{w.Nullifiers[3]})[0], big.NewInt(1))
		},
		"padding gap": func(w *direct.GKRFreshnessCircuit) {
			w.Nullifiers[1], w.Witnesses[1] = 0, direct.NonInclusion{Low: 0, Next: 0, Index: 0, Path: zeros(40)}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := freshness(t, 4)
			mutate(w)
			bindFreshness(t, w)
			if err := test.IsSolved(direct.NewGKRFreshness(4), w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("invalid freshness satisfied the circuit")
			}
		})
	}
}

func TestGKRFreshnessConstraints(t *testing.T) {
	if os.Getenv("SPLIT_NIP_COUNTS") == "" {
		t.Skip("set SPLIT_NIP_COUNTS to compile the wide shapes")
	}
	for _, n := range []int{144, 512} {
		start := time.Now()
		cs := compileGKRFreshness(t, n)
		t.Logf("SPLIT_NIP_COMPILE inputs=%d constraints=%d compile_ms=%d", n, cs.GetNbConstraints(), time.Since(start).Milliseconds())
		cs = nil
		debug.FreeOSMemory()
	}
}

// compileGKRFreshness compiles the shape and checks the commitment layout SPP's
// commitment-aware verifier expects: one private BSB22 commitment, no committed
// public inputs, two public variables (one plus the public hash).
func compileGKRFreshness(t *testing.T, n int) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, direct.NewGKRFreshness(n), frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	commitments := cs.GetCommitments().(constraint.Groth16Commitments)
	if len(commitments) != 1 || len(commitments[0].PublicAndCommitmentCommitted) != 0 || cs.GetNbPublicVariables() != 2 {
		t.Fatal("GKR freshness does not match SPP's single private BSB22 commitment verifier")
	}
	return cs
}

// TestSplitNipProving measures the public half alone: setup in memory unless
// SPLIT_NIP_KEYS holds nullifier-freshness-gkr_<n>_0.key, then three verified
// proofs with resident keys.
func TestSplitNipProving(t *testing.T) {
	n := splitNipInputs(t)
	t.Logf("go=%s arch=%s cpus=%d gomaxprocs=%d memory_limit=%s", runtime.Version(), runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), os.Getenv("GOMEMLIMIT"))
	start := time.Now()
	w := freshness(t, n)
	t.Logf("SPLIT_NIP_WITNESS inputs=%d build_ms=%d", n, time.Since(start).Milliseconds())
	ps := gkrFreshnessSystem(t, n)
	provePayment(t, "nip_gkr", n, 0, ps.ConstraintSystem, ps.ProvingKey, ps.VerifyingKey, w)
}

// TestSplitNipConcurrentProving is the experiment: the private half
// (direct-payment-admitted) and the public half (nullifier-freshness-gkr) of
// one 512-input spend, proven sequentially and then concurrently on the same
// machine, all proofs verified. Requires SPLIT_NIP_KEYS with both key files.
func TestSplitNipConcurrentProving(t *testing.T) {
	n := splitNipInputs(t)
	if os.Getenv("SPLIT_NIP_KEYS") == "" {
		t.Skip("set SPLIT_NIP_KEYS to a directory holding direct-payment-admitted_<n>_2.key and nullifier-freshness-gkr_<n>_0.key")
	}
	samples := 3
	if value, err := strconv.Atoi(os.Getenv("SPLIT_NIP_SAMPLES")); err == nil && value > 0 {
		samples = value
	}
	t.Logf("go=%s arch=%s cpus=%d gomaxprocs=%d memory_limit=%s samples=%d", runtime.Version(), runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), os.Getenv("GOMEMLIMIT"), samples)

	start := time.Now()
	private := admittedPayment(t, scatteredPayment(t, n))
	t.Logf("SPLIT_NIP_WITNESS half=private inputs=%d build_ms=%d", n, time.Since(start).Milliseconds())
	start = time.Now()
	public := freshness(t, n)
	t.Logf("SPLIT_NIP_WITNESS half=public inputs=%d build_ms=%d", n, time.Since(start).Milliseconds())

	manager := common.NewLazyKeyManager(os.Getenv("SPLIT_NIP_KEYS"), &common.DownloadConfig{AutoDownload: false})
	start = time.Now()
	privateSystem, err := manager.GetTransferSystem(common.DirectPaymentAdmittedCircuitType, uint32(n), 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SPLIT_NIP_KEY half=private constraints=%d load_ms=%d", privateSystem.ConstraintSystem.GetNbConstraints(), time.Since(start).Milliseconds())
	start = time.Now()
	publicSystem := gkrFreshnessSystem(t, n)
	t.Logf("SPLIT_NIP_KEY half=public constraints=%d load_ms=%d", publicSystem.ConstraintSystem.GetNbConstraints(), time.Since(start).Milliseconds())

	halves := []struct {
		name string
		ps   *common.TransferProofSystem
		w    frontend.Circuit
	}{{"private", privateSystem, private}, {"public", publicSystem, public}}

	for sample := range samples {
		var sequential time.Duration
		for _, half := range halves {
			elapsed, err := proveVerified(half.ps, half.w)
			if err != nil {
				t.Fatal(err)
			}
			sequential += elapsed
			t.Logf("SPLIT_NIP_PROVE mode=sequential half=%s inputs=%d sample=%d prove_ms=%.3f", half.name, n, sample, ms(elapsed))
		}
		debug.FreeOSMemory()
		var group sync.WaitGroup
		durations := make([]time.Duration, len(halves))
		errors := make([]error, len(halves))
		wall := time.Now()
		for i, half := range halves {
			group.Add(1)
			go func() {
				defer group.Done()
				durations[i], errors[i] = proveVerified(half.ps, half.w)
			}()
		}
		group.Wait()
		elapsed := time.Since(wall)
		for i, half := range halves {
			if errors[i] != nil {
				t.Fatalf("%s half: %v", half.name, errors[i])
			}
			t.Logf("SPLIT_NIP_PROVE mode=concurrent half=%s inputs=%d sample=%d prove_ms=%.3f", half.name, n, sample, ms(durations[i]))
		}
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		t.Logf("SPLIT_NIP_WALL inputs=%d sample=%d sequential_ms=%.3f concurrent_ms=%.3f heap_bytes=%d", n, sample, ms(sequential), ms(elapsed), memory.HeapAlloc)
		debug.FreeOSMemory()
	}
}

// splitNipInputs reads the benchmark shape. 8 is a smoke shape for a real
// Groth16 round trip on small machines; only 144 and 512 have service keys.
func splitNipInputs(t *testing.T) int {
	t.Helper()
	n, err := strconv.Atoi(os.Getenv("SPLIT_NIP_INPUTS"))
	if err != nil || (n != 8 && n != 144 && n != 512) {
		t.Skip("set SPLIT_NIP_INPUTS to 8, 144 or 512")
	}
	return n
}

// gkrFreshnessSystem loads nullifier-freshness-gkr_<n>_0.key from
// SPLIT_NIP_KEYS when present and otherwise runs an in-memory setup, checking
// a loaded key against a fresh compilation of the same shape.
func gkrFreshnessSystem(t *testing.T, n int) *common.TransferProofSystem {
	t.Helper()
	start := time.Now()
	cs := compileGKRFreshness(t, n)
	t.Logf("SPLIT_NIP_COMPILE inputs=%d constraints=%d compile_ms=%d", n, cs.GetNbConstraints(), time.Since(start).Milliseconds())
	if keys := os.Getenv("SPLIT_NIP_KEYS"); keys != "" {
		if _, err := os.Stat(fmt.Sprintf("%s/%s_%d_0.key", keys, common.NullifierFreshnessGKRCircuitType, n)); err == nil {
			expected := constraintDigest(t, cs)
			cs = nil
			debug.FreeOSMemory()
			manager := common.NewLazyKeyManager(keys, &common.DownloadConfig{AutoDownload: false})
			ps, err := manager.GetTransferSystem(common.NullifierFreshnessGKRCircuitType, uint32(n), 0)
			if err != nil {
				t.Fatal(err)
			}
			if actual := constraintDigest(t, ps.ConstraintSystem); actual != expected {
				t.Fatalf("loaded key circuit differs from a fresh compilation: %s != %s", actual, expected)
			}
			return ps
		}
	}
	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SPLIT_NIP_SETUP inputs=%d setup_ms=%d", n, time.Since(start).Milliseconds())
	return &common.TransferProofSystem{CircuitType: common.NullifierFreshnessGKRCircuitType, NInputs: uint32(n),
		ConstraintSystem: cs, ProvingKey: pk, VerifyingKey: vk}
}

// proveVerified is goroutine-safe: it reports rather than fails, so the
// concurrent run can prove both halves and fail on the test goroutine.
func proveVerified(ps *common.TransferProofSystem, assignment frontend.Circuit) (time.Duration, error) {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return 0, err
	}
	public, err := witness.Public()
	if err != nil {
		return 0, err
	}
	start := time.Now()
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	elapsed := time.Since(start)
	if err != nil {
		return 0, err
	}
	return elapsed, groth16.Verify(proof, ps.VerifyingKey, public)
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}
