package common

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type ExtensionCircuit struct {
	Type    CircuitType
	KeyFile string
	Circuit func() frontend.Circuit
	Request func() ExtensionRequest
}

// ExtensionRequest is filled from the whole request body by encoding/json.
type ExtensionRequest interface {
	Assignment() (frontend.Circuit, error)
}

type ExtensionProof struct {
	System  *ExtensionProofSystem
	Request ExtensionRequest
	Prover  Prover
}

type ExtensionConvert struct {
	Circuit          ExtensionCircuit
	ProvingKeyPath   string
	VerifyingKeyPath string
}

var extensions []ExtensionCircuit

// RegisterExtension runs in an extension package init, before any key lookup.
func RegisterExtension(circuit ExtensionCircuit) {
	if !strings.HasSuffix(circuit.KeyFile, ".key") || circuit.Circuit == nil || circuit.Request == nil {
		panic(fmt.Sprintf("incomplete extension circuit %s", circuit.Type))
	}
	if circuit.Type.IsTransfer() || circuit.Type == BatchAddressAppendCircuitType || circuit.Type.IsExtension() || KeyFileCircuit(circuit.KeyFile) != "" {
		panic(fmt.Sprintf("extension circuit %s or key %s is already registered", circuit.Type, circuit.KeyFile))
	}
	extensions = append(extensions, circuit)
}

func Extensions() []ExtensionCircuit {
	return extensions
}

func LookupExtension(circuitType CircuitType) (ExtensionCircuit, bool) {
	for _, circuit := range extensions {
		if circuit.Type == circuitType {
			return circuit, true
		}
	}
	return ExtensionCircuit{}, false
}

func (c CircuitType) IsExtension() bool {
	_, ok := LookupExtension(c)
	return ok
}

func (c ExtensionCircuit) R1CS() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		c.Circuit(),
		frontend.WithCompressThreshold(300),
	)
}

func (c ExtensionCircuit) Setup() (*ExtensionProofSystem, error) {
	return c.proofSystem(func(ccs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
		return groth16.Setup(ccs)
	})
}

// Run wraps a gnark pk/vk pair without a new setup.
func (c ExtensionConvert) Run() (*ExtensionProofSystem, error) {
	return c.Circuit.proofSystem(func(constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
		pk := groth16.NewProvingKey(ecc.BN254)
		if err := readKey(c.ProvingKeyPath, pk); err != nil {
			return nil, nil, err
		}
		vk := groth16.NewVerifyingKey(ecc.BN254)
		if err := readKey(c.VerifyingKeyPath, vk); err != nil {
			return nil, nil, err
		}
		return pk, vk, nil
	})
}

func (p ExtensionProof) Prove() (*Proof, error) {
	ps := p.System
	proof, err := p.Prover.Run(ps.ConstraintSystem, ps.ProvingKey, p.Request.Assignment)
	if err != nil {
		return nil, err
	}
	return &Proof{Proof: proof, ProvingKeySha256: ps.ProvingKeySha256}, nil
}

func (c ExtensionCircuit) proofSystem(keys func(constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error)) (*ExtensionProofSystem, error) {
	ccs, err := c.R1CS()
	if err != nil {
		return nil, err
	}
	pk, vk, err := keys(ccs)
	if err != nil {
		return nil, err
	}
	return &ExtensionProofSystem{
		CircuitType:      c.Type,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}, nil
}

func readKey(path string, key io.ReaderFrom) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := key.ReadFrom(file); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}
