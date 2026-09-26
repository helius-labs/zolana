package aeglosfixture

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/frontend"
)

type exportCircuit struct {
	Public frontend.Variable `gnark:",public"`
	Secret frontend.Variable
}

func (c *exportCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.Secret, c.Secret), c.Public)
	return nil
}

func TestWriteReplacesFilesWithPrivateDeterministicWitnesses(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("AEGLOS_FIXTURES", directory)
	path := filepath.Join(directory, "test.key.0.witness")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	assignment := &exportCircuit{Public: 361, Secret: 19}
	Write(t, "test.key", 0, assignment)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("witness permissions are not private")
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	Write(t, "test.key", 0, assignment)
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("witness encoding changed")
	}
}

func TestWriteDoesNotFollowExistingSymlink(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("AEGLOS_FIXTURES", directory)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "test.key.0.witness")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	Write(t, "test.key", 0, &exportCircuit{Public: 361, Secret: 19})
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "unchanged" {
		t.Fatal("export changed the symlink target")
	}
}
