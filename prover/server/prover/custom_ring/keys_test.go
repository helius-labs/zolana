package custom_ring

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark/constraint"

	"zolana/prover/prover/common"
)

func TestRingKeysCarryTheCompiledCircuits(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		compile func() (constraint.ConstraintSystem, error)
	}{
		{name: TransferVariant, file: common.CustomRingKeyFile, compile: R1CSCustomRing},
		{name: AuditVariant, file: common.AuditKeyFile, compile: R1CSAudit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loaded := loadRingSystem(t, test.file)
			compiled, err := test.compile()
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			var fromKey, fresh bytes.Buffer
			if _, err := loaded.ConstraintSystem.WriteTo(&fromKey); err != nil {
				t.Fatalf("write key circuit: %v", err)
			}
			if _, err := compiled.WriteTo(&fresh); err != nil {
				t.Fatalf("write compiled circuit: %v", err)
			}
			if !bytes.Equal(fromKey.Bytes(), fresh.Bytes()) {
				t.Fatalf("%s does not carry the compiled circuit, %d against %d constraints, rotate the keys",
					test.file, loaded.ConstraintSystem.GetNbConstraints(), compiled.GetNbConstraints())
			}
		})
	}
}

// Skips the test when proving-keys/<file> is absent.
func loadRingSystem(t *testing.T, file string) *common.RingProofSystem {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "proving-keys", file)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is not available", file)
	}
	loaded, err := common.ReadSystemFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	system, ok := loaded.(*common.RingProofSystem)
	if !ok {
		t.Fatalf("unexpected proof system %T", loaded)
	}
	return system
}
