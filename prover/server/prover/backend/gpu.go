//go:build aeglos

package backend

import aeglos "github.com/helius-labs/aeglos"

const defaultBackend = "aeglos"

func newGPU() (prover, error) {
	limit, err := memoryLimit()
	if err != nil {
		return nil, err
	}
	return aeglos.New(aeglos.Config{MemoryLimitBytes: limit, Observe: observe("aeglos")})
}
