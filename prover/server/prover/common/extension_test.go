package common

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/frontend"
)

type squareCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *squareCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

type squareRequest struct {
	X, Y int
}

func (r *squareRequest) Assignment() (frontend.Circuit, error) {
	return &squareCircuit{X: r.X, Y: r.Y}, nil
}

var squareExtension = ExtensionCircuit{
	Type:    "test-square",
	KeyFile: "test_square.key",
	Circuit: func() frontend.Circuit { return new(squareCircuit) },
	Request: func() ExtensionRequest { return new(squareRequest) },
}

func withSquareExtension(t *testing.T) {
	t.Helper()
	RegisterExtension(squareExtension)
	t.Cleanup(func() { extensions = nil })
}

func TestRegisterExtensionRejectsTakenNames(t *testing.T) {
	withSquareExtension(t)
	for name, circuit := range map[string]ExtensionCircuit{
		"circuit":       {Type: squareExtension.Type, KeyFile: "other.key", Circuit: squareExtension.Circuit, Request: squareExtension.Request},
		"key":           {Type: "other", KeyFile: squareExtension.KeyFile, Circuit: squareExtension.Circuit, Request: squareExtension.Request},
		"built-in key":  {Type: "other", KeyFile: "merge_24_1.key", Circuit: squareExtension.Circuit, Request: squareExtension.Request},
		"built-in type": {Type: MergeCircuitType, KeyFile: "other.key", Circuit: squareExtension.Circuit, Request: squareExtension.Request},
		"no suffix":     {Type: "other", KeyFile: "other", Circuit: squareExtension.Circuit, Request: squareExtension.Request},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("registration accepted")
				}
			}()
			RegisterExtension(circuit)
		})
	}
}

func TestExtensionKeyRoundTripsAndProves(t *testing.T) {
	withSquareExtension(t)
	if KeyFileCircuit(squareExtension.KeyFile) != squareExtension.Type {
		t.Fatal("extension key is not a key file")
	}
	ps, err := squareExtension.Setup()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), squareExtension.KeyFile)
	if err := WriteProvingSystem(ps, path, ""); err != nil {
		t.Fatal(err)
	}
	loaded, err := NewLazyKeyManager(filepath.Dir(path), &DownloadConfig{}).GetExtensionSystem(squareExtension.Type)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (ExtensionProof{System: loaded, Request: &squareRequest{X: 3, Y: 9}}).Prove(); err != nil {
		t.Fatal(err)
	}
	if _, err := (ExtensionProof{System: loaded, Request: &squareRequest{X: 3, Y: 8}}).Prove(); err == nil {
		t.Fatal("false statement proved")
	}
	var written, read bytes.Buffer
	if _, err := ps.VerifyingKey.WriteTo(&written); err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.VerifyingKey.WriteTo(&read); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written.Bytes(), read.Bytes()) {
		t.Fatal("reloaded verifying key differs")
	}
}
