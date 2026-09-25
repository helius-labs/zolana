//go:build !aeglos

package backend

import "fmt"

const defaultBackend = "gnark"

func newGPU() (prover, error) { return nil, fmt.Errorf("Aeglos backend requires the aeglos build tag") }
