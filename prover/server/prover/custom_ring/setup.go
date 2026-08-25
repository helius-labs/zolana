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

type ConvertCustomRingAudit struct {
	ProvingKeyPath   string
	VerifyingKeyPath string
}

func SetupCustomRingAudit() (*common.RingProofSystem, error) {
	fmt.Println("Setting up custom-ring-audit")
	ccs, err := R1CSCustomRingAudit()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return proofSystem(pk, vk, ccs), nil
}

func (c ConvertCustomRingAudit) Run() (*common.RingProofSystem, error) {
	ccs, err := R1CSCustomRingAudit()
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

type ConvertCustomRingPolicy struct {
	ProvingKeyPath   string
	VerifyingKeyPath string
}

func SetupCustomRingPolicy() (*common.RingProofSystem, error) {
	fmt.Println("Setting up custom-ring-policy")
	ccs, err := R1CSCustomRingPolicy()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, err
	}
	return policyProofSystem(pk, vk, ccs), nil
}

func (c ConvertCustomRingPolicy) Run() (*common.RingProofSystem, error) {
	ccs, err := R1CSCustomRingPolicy()
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
	return policyProofSystem(pk, vk, ccs), nil
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

func policyProofSystem(pk groth16.ProvingKey, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) *common.RingProofSystem {
	return &common.RingProofSystem{
		CircuitType:      policyCircuitType,
		Variant:          TransferVariant,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
}

func proofSystem(pk groth16.ProvingKey, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) *common.RingProofSystem {
	return &common.RingProofSystem{
		CircuitType:      common.CustomRingAuditCircuitType,
		Variant:          TransferVariant,
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
	}
}
