package aeglosfixture

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func Write(t testing.TB, name string, index int, assignment frontend.Circuit) {
	t.Helper()
	directory := os.Getenv("AEGLOS_FIXTURES")
	if directory == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	if err := test.IsSolved(assignment, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("fixture %s %d does not satisfy circuit", name, index)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(directory, ".witness-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	_, writeErr := full.WriteTo(file)
	closeErr := file.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if err := os.Rename(file.Name(), filepath.Join(directory, fmt.Sprintf("%s.%d.witness", name, index))); err != nil {
		t.Fatal(err)
	}
}
