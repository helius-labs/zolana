//go:build aeglos

package backend

import (
	"fmt"
	"os"
	"strconv"

	aeglos "github.com/helius-labs/aeglos"
)

const defaultBackend = "aeglos"

func newGPU() (prover, error) {
	var limit uint64
	if value := os.Getenv("AEGLOS_MEMORY_LIMIT_BYTES"); value != "" {
		var err error
		limit, err = strconv.ParseUint(value, 10, 64)
		if err != nil || limit == 0 {
			return nil, fmt.Errorf("invalid AEGLOS_MEMORY_LIMIT_BYTES %q", value)
		}
	}
	return aeglos.New(aeglos.Config{MemoryLimitBytes: limit, Observe: observeGPU})
}
