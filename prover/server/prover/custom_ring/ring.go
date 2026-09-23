package custom_ring

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	base "zolana/prover/custom_rings/circuits/base"
	"zolana/prover/custom_rings/circuits/deposit"
	"zolana/prover/custom_rings/circuits/policy"
	"zolana/prover/prover/common"
)

// Keeps each ring statement's decoder and compiled witness shape together.
type RingCircuit struct {
	Type    common.CircuitType
	circuit func() frontend.Circuit
	request func() Request
}

type Request interface {
	assignment() (frontend.Circuit, error)
}

type Convert struct {
	Circuit          RingCircuit
	ProvingKeyPath   string
	VerifyingKeyPath string
}

var (
	policyRing = RingCircuit{
		Type:    common.CustomRingPolicyCircuitType,
		circuit: func() frontend.Circuit { return &policy.CustomRingPolicyCircuit{} },
		request: func() Request { return new(PolicyParameters) },
	}
	baseRing = RingCircuit{
		Type:    common.CustomRingBaseCircuitType,
		circuit: func() frontend.Circuit { return &base.CustomRingBaseCircuit{} },
		request: func() Request { return new(BaseParameters) },
	}
	delegatePolicyRing = RingCircuit{
		Type:    common.CustomRingDelegatePolicyCircuitType,
		circuit: func() frontend.Circuit { return &policy.CustomRingDelegatePolicyCircuit{} },
		request: func() Request { return new(DelegatePolicyParameters) },
	}
	compressedPolicyRing = RingCircuit{
		Type:    common.CustomRingCompressedPolicyCircuitType,
		circuit: func() frontend.Circuit { return &policy.CompressedPolicyCircuit{} },
		request: func() Request { return new(CompressedPolicyParameters) },
	}
	keyRegisterRing = RingCircuit{
		Type:    common.CustomRingKeyRegisterCircuitType,
		circuit: func() frontend.Circuit { return &policy.KeyRegisterCircuit{} },
		request: func() Request { return new(KeyRegisterParameters) },
	}
	depositRing = RingCircuit{
		Type:    common.CustomRingDepositCircuitType,
		circuit: func() frontend.Circuit { return &deposit.CustomRingDepositCircuit{} },
		request: func() Request { return new(DepositParameters) },
	}
)

var RingCircuits = []RingCircuit{
	policyRing,
	baseRing,
	delegatePolicyRing,
	compressedPolicyRing,
	keyRegisterRing,
	depositRing,
}

func R1CSPolicy() (constraint.ConstraintSystem, error) {
	return policyRing.R1CS()
}

func R1CSBase() (constraint.ConstraintSystem, error) {
	return baseRing.R1CS()
}

func R1CSDelegatePolicy() (constraint.ConstraintSystem, error) {
	return delegatePolicyRing.R1CS()
}

func R1CSCompressedPolicy() (constraint.ConstraintSystem, error) {
	return compressedPolicyRing.R1CS()
}

func R1CSKeyRegister() (constraint.ConstraintSystem, error) {
	return keyRegisterRing.R1CS()
}

func R1CSDeposit() (constraint.ConstraintSystem, error) {
	return depositRing.R1CS()
}

func (r RingCircuit) R1CS() (constraint.ConstraintSystem, error) {
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		r.circuit(),
		frontend.WithCompressThreshold(300),
	)
}

func (r RingCircuit) Setup() (*common.RingProofSystem, error) {
	return r.proofSystem(func(ccs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
		return groth16.Setup(ccs)
	})
}

func (c Convert) Run() (*common.RingProofSystem, error) {
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

func DecodeRequest(circuitType common.CircuitType, payload []byte) (Request, error) {
	for _, ring := range RingCircuits {
		if ring.Type != circuitType {
			continue
		}
		request := ring.request()
		if err := json.Unmarshal(payload, request); err != nil {
			return nil, err
		}
		return request, nil
	}
	return nil, fmt.Errorf("unknown custom-ring circuit type: %s", circuitType)
}

func Prove(ps *common.RingProofSystem, request Request) (*common.Proof, error) {
	assignment, err := request.assignment()
	if err != nil {
		return nil, err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}

func (p *PolicyParameters) assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *BaseParameters) assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *DelegatePolicyParameters) assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *CompressedPolicyParameters) assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *KeyRegisterParameters) assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *DepositParameters) assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (r RingCircuit) proofSystem(keys func(constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error)) (*common.RingProofSystem, error) {
	ccs, err := r.R1CS()
	if err != nil {
		return nil, err
	}
	pk, vk, err := keys(ccs)
	if err != nil {
		return nil, err
	}
	return &common.RingProofSystem{
		CircuitType:      r.Type,
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
