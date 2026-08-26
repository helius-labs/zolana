package custom_ring

import (
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"

	"zolana/prover/prover/common"
)

type ConvertCustomRing struct {
	ProvingKeyPath   string
	VerifyingKeyPath string
}

func SetupCustomRing() (*common.RingProofSystem, error) {
	fmt.Println("Setting up custom-ring")
	ccs, err := R1CSCustomRing()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return proofSystem(pk, vk, ccs), nil
}

func (c ConvertCustomRing) Run() (*common.RingProofSystem, error) {
	ccs, err := R1CSCustomRing()
	if err != nil {
		return nil, err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readKey(c.ProvingKeyPath, pk); err != nil {
		return nil, err
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readKey(c.VerifyingKeyPath, vk); err != nil {
		return nil, err
	}
	return proofSystem(pk, vk, ccs), nil
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

func proofSystem(pk groth16.ProvingKey, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) *common.RingProofSystem {
	return &common.RingProofSystem{
		CircuitType:      common.CustomRingCircuitType,
		Variant:          TransferVariant,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
}
