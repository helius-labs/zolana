//go:build !aeglos

package backend

import "fmt"

func newGPU() (prover, error) { return nil, fmt.Errorf("Aeglos backend requires the aeglos build tag") }
