package gpuprove

import (
	"strings"
	"sync"
	"testing"
)

func resetMode(t *testing.T) {
	t.Helper()
	modeOnce = sync.Once{}
	modeErr = nil
	t.Cleanup(func() {
		modeOnce = sync.Once{}
		modeErr = nil
	})
}

func resetMinConstraints(t *testing.T) {
	t.Helper()
	minConstraintsOnce = sync.Once{}
	t.Cleanup(func() { minConstraintsOnce = sync.Once{} })
}

// Pins the auto-mode routing default. The threshold is the measured
// gpu/cpu crossover, BENCHMARKS.md holds the numbers.
func TestMinGPUConstraintsDefaultIs80000(t *testing.T) {
	resetMinConstraints(t)
	t.Setenv("PROVER_GPU_MIN_CONSTRAINTS", "")
	if got := minGPUConstraints(); got != 80000 {
		t.Errorf("minGPUConstraints() = %d, want 80000", got)
	}
}

func TestMinGPUConstraintsEnvOverride(t *testing.T) {
	resetMinConstraints(t)
	t.Setenv("PROVER_GPU_MIN_CONSTRAINTS", "120000")
	if got := minGPUConstraints(); got != 120000 {
		t.Errorf("minGPUConstraints() = %d, want 120000", got)
	}
}

func TestMinGPUConstraintsInvalidEnvKeepsDefault(t *testing.T) {
	resetMinConstraints(t)
	t.Setenv("PROVER_GPU_MIN_CONSTRAINTS", "not-a-number")
	if got := minGPUConstraints(); got != 80000 {
		t.Errorf("minGPUConstraints() = %d, want 80000", got)
	}
}

// PROVER_GPU=off must force the CPU in every build.
func TestOffForcesCPU(t *testing.T) {
	resetMode(t)
	t.Setenv("PROVER_GPU", "off")
	gpu, err := UseGPU()
	if err != nil || gpu {
		t.Errorf("UseGPU() = %v, %v, want false, nil", gpu, err)
	}
}

// auto selects the GPU only when the build carries it and a device answers.
// In the default build both are false, so auto is the CPU.
func TestAutoFollowsBuildAndDevice(t *testing.T) {
	resetMode(t)
	t.Setenv("PROVER_GPU", "auto")
	gpu, err := UseGPU()
	if err != nil {
		t.Fatalf("UseGPU() error: %v", err)
	}
	if want := gpuBuilt && gpuAvailable(); gpu != want {
		t.Errorf("UseGPU() = %v, want %v", gpu, want)
	}
}

// on must error instead of downgrading when the GPU cannot serve.
func TestOnErrorsWithoutGPU(t *testing.T) {
	resetMode(t)
	t.Setenv("PROVER_GPU", "on")
	gpu, err := UseGPU()
	if gpuBuilt && gpuAvailable() {
		if err != nil || !gpu {
			t.Errorf("UseGPU() = %v, %v, want true, nil", gpu, err)
		}
		return
	}
	if err == nil {
		t.Fatal("UseGPU() = nil error, want an error without a usable device")
	}
	if gpu {
		t.Error("UseGPU() reported the GPU usable alongside an error")
	}
}

func TestInvalidModeErrors(t *testing.T) {
	resetMode(t)
	t.Setenv("PROVER_GPU", "maybe")
	if _, err := UseGPU(); err == nil || !strings.Contains(err.Error(), "PROVER_GPU") {
		t.Errorf("UseGPU() error = %v, want an invalid PROVER_GPU error", err)
	}
}
