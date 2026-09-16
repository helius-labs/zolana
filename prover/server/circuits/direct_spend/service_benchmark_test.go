package directspend_test

import (
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"

	"zolana/prover/prover/common"
	directprover "zolana/prover/prover/direct_spend"
)

func TestGKRServiceProving(t *testing.T) {
	keys := os.Getenv("GKR_SERVICE_KEYS")
	if keys == "" {
		t.Skip("set GKR_SERVICE_KEYS to benchmark local experimental keys")
	}
	inputs, err := strconv.Atoi(os.Getenv("GKR_SERVICE_INPUTS"))
	if err != nil || (inputs != 144 && inputs != 512) {
		t.Fatal("GKR_SERVICE_INPUTS must be 144 or 512")
	}
	kind := common.DirectPaymentGKRCircuitType
	if name := os.Getenv("GKR_SERVICE_CIRCUIT"); name != "" {
		kind = common.CircuitType(name)
	}
	if kind != common.DirectPaymentGKRCircuitType && kind != common.DirectPaymentAdmittedCircuitType {
		t.Fatal("GKR_SERVICE_CIRCUIT must be direct-payment-gkr or direct-payment-admitted")
	}
	samples := benchmarkValues(t, "GKR_SERVICE_SAMPLES", "3")[0]
	threads := benchmarkValues(t, "GKR_SERVICE_THREADS", "4,8,18")
	concurrency := benchmarkValues(t, "GKR_SERVICE_CONCURRENCY", "1")
	msmTasks := []int{0}
	if os.Getenv("GKR_SERVICE_MSM_TASKS") != "" {
		msmTasks = benchmarkValues(t, "GKR_SERVICE_MSM_TASKS", "18")
	}
	originalThreads := runtime.GOMAXPROCS(threads[0])
	defer runtime.GOMAXPROCS(originalThreads)
	circuit, err := directprover.Circuit(kind, uint32(inputs), 2)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	expected := constraintDigest(t, compiled)
	compiled = nil
	debug.FreeOSMemory()
	payment := scatteredPayment(t, inputs)
	var w frontend.Circuit = payment
	if kind == common.DirectPaymentAdmittedCircuitType {
		w = admittedPayment(t, payment)
	}
	encoded, err := json.Marshal(witnessJSON(t, reflect.ValueOf(w).Elem()))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(directprover.Request{CircuitType: kind, NInputs: uint32(inputs), NOutputs: 2, Witness: encoded})
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	manager := common.NewLazyKeyManager(keys, &common.DownloadConfig{AutoDownload: false})
	start := time.Now()
	ps, err := manager.GetTransferSystem(kind, uint32(inputs), 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GKR_SERVICE_LOAD kind=%s inputs=%d load_ms=%d constraints=%d request_bytes=%d go=%s", kind, inputs, time.Since(start).Milliseconds(), ps.ConstraintSystem.GetNbConstraints(), len(body), runtime.Version())
	if actual := constraintDigest(t, ps.ConstraintSystem); actual != expected {
		t.Fatalf("loaded key circuit differs from service factory: %s != %s", actual, expected)
	}
	t.Logf("GKR_SERVICE_KEY inputs=%d digest=%s", inputs, expected)
	if os.Getenv("GKR_SERVICE_VALIDATE_ONLY") != "" {
		return
	}
	if path := os.Getenv("GKR_SERVICE_PROFILE"); path != "" {
		profile, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := pprof.StartCPUProfile(profile); err != nil {
			profile.Close()
			t.Fatal(err)
		}
		defer func() { pprof.StopCPUProfile(); profile.Close() }()
		previous := logger.Logger()
		logger.Set(zerolog.New(os.Stdout).With().Timestamp().Logger())
		defer logger.Set(previous)
	}
	for _, tasks := range msmTasks {
		t.Setenv("ZOLANA_MSM_TASKS", strconv.Itoa(tasks))
		for _, count := range threads {
			runtime.GOMAXPROCS(count)
			for _, concurrent := range concurrency {
				debug.FreeOSMemory()
				var durations, walls []float64
				for sample := 0; sample < samples; sample++ {
					proofs := make([][]byte, concurrent)
					errors := make([]error, concurrent)
					elapsed := make([]time.Duration, concurrent)
					var wg sync.WaitGroup
					start := time.Now()
					for i := range concurrent {
						wg.Add(1)
						go func(i int) {
							defer wg.Done()
							start := time.Now()
							proof, err := directprover.ProveRequest(manager, body)
							if err == nil {
								proofs[i], err = json.Marshal(proof)
							}
							elapsed[i], errors[i] = time.Since(start), err
						}(i)
					}
					wg.Wait()
					wall := time.Since(start).Seconds()
					walls = append(walls, wall)
					for i := range concurrent {
						if errors[i] != nil {
							t.Fatal(errors[i])
						}
						var proof common.Proof
						if err := json.Unmarshal(proofs[i], &proof); err != nil {
							t.Fatal(err)
						}
						if err := groth16.Verify(proof.Proof, ps.VerifyingKey, public); err != nil {
							t.Fatal(err)
						}
						durations = append(durations, elapsed[i].Seconds())
						t.Logf("GKR_SERVICE_PROVE inputs=%d threads=%d msm_tasks=%d concurrency=%d sample=%d request=%d seconds=%.6f", inputs, count, tasks, concurrent, sample, i, elapsed[i].Seconds())
					}
					var memory runtime.MemStats
					runtime.ReadMemStats(&memory)
					t.Logf("GKR_SERVICE_WAVE inputs=%d threads=%d concurrency=%d sample=%d seconds=%.6f heap_bytes=%d sys_bytes=%d", inputs, count, concurrent, sample, wall, memory.HeapAlloc, memory.Sys)
				}
				sort.Float64s(durations)
				sort.Float64s(walls)
				t.Logf("GKR_SERVICE_MEDIAN inputs=%d threads=%d msm_tasks=%d concurrency=%d latency_seconds=%.6f wave_seconds=%.6f proofs_per_second=%.6f", inputs, count, tasks, concurrent, median(durations), median(walls), float64(concurrent)/median(walls))
			}
		}
	}
}

func median(values []float64) float64 {
	n := len(values)
	return (values[(n-1)/2] + values[n/2]) / 2
}

func benchmarkValues(t *testing.T, name, fallback string) []int {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		value = fallback
	}
	var result []int
	for _, part := range strings.Split(value, ",") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 {
			t.Fatalf("invalid %s: %s", name, value)
		}
		result = append(result, n)
	}
	return result
}

func witnessJSON(t *testing.T, value reflect.Value) any {
	t.Helper()
	switch value.Kind() {
	case reflect.Struct:
		result := map[string]any{}
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if field.Tag.Get("gnark") != "-" {
				result[field.Name] = witnessJSON(t, value.Field(i))
			}
		}
		return result
	case reflect.Slice:
		result := make([]any, value.Len())
		for i := range result {
			result[i] = witnessJSON(t, value.Index(i))
		}
		return result
	case reflect.Interface:
		return common.ToHex(integers(t, []frontend.Variable{value.Interface()})[0])
	default:
		t.Fatalf("unsupported witness field %s", value.Kind())
		return nil
	}
}
