//go:build aeglos_cpu

package backend

import (
	"fmt"
	"os"
	"strconv"

	aeglos "github.com/helius-labs/aeglos"
)

// Collides with gpu.go to keep the two Aeglos tags exclusive.
const defaultBackend = "aeglos-cpu"

func newAeglosCPU() (prover, error) {
	config := aeglos.Config{Backend: aeglos.BackendCPU, Observe: observe("aeglos-cpu")}
	var err error
	if config.MemoryLimitBytes, err = memoryLimit(); err != nil {
		return nil, err
	}
	if value := os.Getenv("AEGLOS_CPU_THREADS"); value != "" {
		if config.Threads, err = strconv.Atoi(value); err != nil || config.Threads < 1 {
			return nil, fmt.Errorf("invalid AEGLOS_CPU_THREADS %q", value)
		}
	}
	if value := os.Getenv("AEGLOS_CPU_FAMILY"); value != "" {
		if config.CPUFamily, err = cpuFamily(value); err != nil {
			return nil, err
		}
	}
	return aeglos.New(config)
}

func cpuFamily(name string) (aeglos.CPUFamily, error) {
	for _, family := range []aeglos.CPUFamily{aeglos.CPUAuto, aeglos.CPUScalar, aeglos.CPUAVX512F, aeglos.CPUIFMA256, aeglos.CPUIFMA512} {
		if family.String() == name {
			return family, nil
		}
	}
	return aeglos.CPUAuto, fmt.Errorf("invalid AEGLOS_CPU_FAMILY %q", name)
}
