//go:build !aeglos

package backend

import "testing"

func TestUnsetBackendIsCPUWithoutBuildSupport(t *testing.T) {
	resetBackend(t)
	t.Setenv("PROVER_BACKEND", "")
	if err := Initialize(); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.prover.(cpuProver); !ok {
		t.Fatal("CPU backend was not selected")
	}
}

func TestGPUSelectionRequiresBuildSupport(t *testing.T) {
	resetBackend(t)
	t.Setenv("PROVER_BACKEND", "aeglos")
	if err := Initialize(); err == nil {
		t.Fatal("GPU selection succeeded without build support")
	}
	if _, err := prove(nil, nil, nil); err == nil {
		t.Fatal("CPU proof remained available after GPU selection failed")
	}
}
