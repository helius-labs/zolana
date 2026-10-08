//go:build aeglos || aeglos_cpu

package backend

import (
	"fmt"
	"os"
	"strconv"
)

func memoryLimit() (uint64, error) {
	value := os.Getenv("AEGLOS_MEMORY_LIMIT_BYTES")
	if value == "" {
		return 0, nil
	}
	limit, err := strconv.ParseUint(value, 10, 64)
	if err != nil || limit == 0 {
		return 0, fmt.Errorf("invalid AEGLOS_MEMORY_LIMIT_BYTES %q", value)
	}
	return limit, nil
}
