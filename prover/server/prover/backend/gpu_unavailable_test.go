//go:build !aeglos

package backend

import "testing"

func TestGPUSelectionRequiresBuildSupport(t *testing.T) {
	resetBackend(t)
	t.Setenv("PROVER_BACKEND", "aeglos")
	if err := Initialize(); err == nil {
		t.Fatal("GPU selection succeeded without build support")
	}
	if _, err := Prove(nil, nil, nil); err == nil {
		t.Fatal("CPU proof remained available after GPU selection failed")
	}
}
