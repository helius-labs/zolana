//go:build !aeglos_cpu

package backend

import "fmt"

func newAeglosCPU() (prover, error) {
	return nil, fmt.Errorf("Aeglos CPU backend requires the aeglos_cpu build tag")
}
