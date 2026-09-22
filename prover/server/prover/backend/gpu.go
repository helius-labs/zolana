//go:build aeglos

package backend

import (
	"fmt"
	"os"
	"strconv"

	aeglos "github.com/helius-labs/aeglos"
)

func newGPU() (prover, error) {
	var limit uint64
	if value := os.Getenv("AEGLOS_MEMORY_LIMIT_BYTES"); value != "" {
		var err error
		limit, err = strconv.ParseUint(value, 10, 64)
		if err != nil || limit == 0 {
			return nil, fmt.Errorf("invalid Aeglos memory limit")
		}
	}
	return aeglos.New(aeglos.Config{MemoryLimitBytes: limit, Observe: observeGPU})
}
