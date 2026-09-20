package transaction

import (
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type benchOptions struct {
	keys, output, profileDir string
	requests, repeats        int
	rtts, workers, clients   []int
	modes                    []string
}

type benchEnvironment struct {
	BuildSettings map[string]string `json:"build_settings"`
	GoVersion     string            `json:"go_version"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	CPUs          int               `json:"cpus"`
	MaxProcs      int               `json:"gomaxprocs"`
	GOGC          string            `json:"gogc"`
	MemoryLimit   string            `json:"gomemlimit"`
}

type benchResources struct {
	cpuSeconds float64
	peakRSS    uint64
}

func readBenchOptions(t *testing.T) benchOptions {
	t.Helper()
	options := benchOptions{
		keys: os.Getenv("PROVER_BENCH_KEYS"), output: os.Getenv("PROVER_BENCH_OUTPUT"),
		profileDir: os.Getenv("PROVER_BENCH_PROFILE_DIR"),
		requests:   benchScalar(t, "PROVER_BENCH_REQUESTS", "200"),
		repeats:    benchScalar(t, "PROVER_BENCH_REPEATS", "3"),
		rtts:       benchIntegers(t, "PROVER_BENCH_RTT_MS", "70", 0),
		workers:    benchIntegers(t, "PROVER_BENCH_WORKERS", "1,2,4", 1),
		clients:    benchIntegers(t, "PROVER_BENCH_CLIENTS", "1,4,8", 1),
		modes:      []string{"direct", "client_fetch", "prover_fetch"},
	}
	if options.keys == "" || options.output == "" {
		t.Fatal("benchmark paths required")
	}
	if value := os.Getenv("PROVER_BENCH_MODES"); value != "" {
		modes := strings.Split(value, ",")
		for index, mode := range modes {
			if !slices.Contains(options.modes, mode) || slices.Contains(modes[:index], mode) {
				t.Fatalf("invalid benchmark mode %q", mode)
			}
		}
		options.modes = modes
	}
	if options.profileDir != "" {
		if err := os.MkdirAll(options.profileDir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return options
}

func (o benchOptions) maxClients() int {
	return slices.Max(o.clients)
}

func benchScalar(t *testing.T, name, fallback string) int {
	t.Helper()
	values := benchIntegers(t, name, fallback, 1)
	if len(values) != 1 {
		t.Fatalf("%s requires one value", name)
	}
	return values[0]
}

func benchIntegers(t *testing.T, name, fallback string, minimum int) []int {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		value = fallback
	}
	var values []int
	for _, part := range strings.Split(value, ",") {
		number, err := strconv.Atoi(part)
		if err != nil || number < minimum || slices.Contains(values, number) {
			t.Fatalf("invalid %s value %q", name, value)
		}
		values = append(values, number)
	}
	return values
}

func benchBuildSettings() map[string]string {
	settings := make(map[string]string)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "GOAMD64", "GOARM64", "-pgo", "-gcflags", "-race", "CGO_ENABLED":
				settings[setting.Key] = setting.Value
			}
		}
	}
	return settings
}

func benchUsage(t *testing.T) benchResources {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	rss := uint64(usage.Maxrss)
	if runtime.GOOS == "linux" {
		rss *= 1024
	}
	return benchResources{
		cpuSeconds: float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6,
		peakRSS:    rss,
	}
}
