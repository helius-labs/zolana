package custom_ring

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover/common"
)

// CompressedRegisterParameters supplies an unverified head registration request.
type CompressedRegisterParameters struct {
	PublicInputHash *big.Int
	HeadOldRoot     *big.Int
	HeadNewRoot     *big.Int
	Member          *big.Int
	Genesis         *big.Int
	NewIndex        *big.Int
	LowMember       *big.Int
	LowNext         *big.Int
	LowNullifier    *big.Int
	LowIndex        *big.Int
	LowProof        [policy.HeadMapHeight]*big.Int
	NewProof        [policy.HeadMapHeight]*big.Int
}

// compressedRegisterParametersJSON encodes the insertion statement and its two Merkle paths.
type compressedRegisterParametersJSON struct {
	CircuitType     string   `json:"circuitType"`
	PublicInputHash string   `json:"publicInputHash"`
	HeadOldRoot     string   `json:"headOldRoot"`
	HeadNewRoot     string   `json:"headNewRoot"`
	Member          string   `json:"member"`
	Genesis         string   `json:"genesis"`
	NewIndex        string   `json:"newIndex"`
	LowMember       string   `json:"lowMember"`
	LowNext         string   `json:"lowNext"`
	LowNullifier    string   `json:"lowNullifier"`
	LowIndex        string   `json:"lowIndex"`
	LowProof        []string `json:"lowProof"`
	NewProof        []string `json:"newProof"`
}

func (p *CompressedRegisterParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(compressedRegisterParametersJSON{
		CircuitType:     string(common.CompressedRegisterCircuitType),
		PublicInputHash: common.ToHex(p.PublicInputHash),
		HeadOldRoot:     common.ToHex(p.HeadOldRoot),
		HeadNewRoot:     common.ToHex(p.HeadNewRoot),
		Member:          common.ToHex(p.Member),
		Genesis:         common.ToHex(p.Genesis),
		NewIndex:        common.ToHex(p.NewIndex),
		LowMember:       common.ToHex(p.LowMember),
		LowNext:         common.ToHex(p.LowNext),
		LowNullifier:    common.ToHex(p.LowNullifier),
		LowIndex:        common.ToHex(p.LowIndex),
		LowProof:        writePath(p.LowProof[:]),
		NewProof:        writePath(p.NewProof[:]),
	})
}

func (p *CompressedRegisterParameters) UnmarshalJSON(data []byte) error {
	// 1. Require the registration rail and complete predecessor and append paths.
	var raw compressedRegisterParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.CompressedRegisterCircuitType) {
		return fmt.Errorf("custom-ring-compressed-register: unexpected circuitType %q", raw.CircuitType)
	}
	if len(raw.LowProof) != policy.HeadMapHeight || len(raw.NewProof) != policy.HeadMapHeight {
		return fmt.Errorf("custom-ring-compressed-register: proof length is not %d", policy.HeadMapHeight)
	}
	// 2. Decode canonical field values without modular reduction.
	scalars := []struct {
		dst  **big.Int
		src  string
		name string
	}{
		{&p.PublicInputHash, raw.PublicInputHash, "publicInputHash"},
		{&p.HeadOldRoot, raw.HeadOldRoot, "headOldRoot"},
		{&p.HeadNewRoot, raw.HeadNewRoot, "headNewRoot"},
		{&p.Member, raw.Member, "member"},
		{&p.Genesis, raw.Genesis, "genesis"},
		{&p.NewIndex, raw.NewIndex, "newIndex"},
		{&p.LowMember, raw.LowMember, "lowMember"},
		{&p.LowNext, raw.LowNext, "lowNext"},
		{&p.LowNullifier, raw.LowNullifier, "lowNullifier"},
		{&p.LowIndex, raw.LowIndex, "lowIndex"},
	}
	for _, s := range scalars {
		value, err := fieldFromHex(s.src, s.name)
		if err != nil {
			return err
		}
		*s.dst = value
	}
	// 3. Require an append position beyond the predecessor and a strict member interval.
	if p.NewIndex.Sign() == 0 || p.NewIndex.BitLen() > policy.HeadMapHeight ||
		p.LowIndex.Cmp(p.NewIndex) >= 0 || p.LowMember.Cmp(p.Member) >= 0 || p.Member.Cmp(p.LowNext) >= 0 {
		return fmt.Errorf("compressed registration has an invalid insertion index or member range")
	}
	for i := range p.LowProof {
		low, err := fieldFromHex(raw.LowProof[i], "lowProof")
		if err != nil {
			return err
		}
		p.LowProof[i] = low
		sibling, err := fieldFromHex(raw.NewProof[i], "newProof")
		if err != nil {
			return err
		}
		p.NewProof[i] = sibling
	}
	return nil
}

func (p *CompressedRegisterParameters) CreateWitness() (*policy.CompressedRegisterCircuit, error) {
	circuit := &policy.CompressedRegisterCircuit{
		PublicInputHash: p.PublicInputHash,
		HeadOldRoot:     p.HeadOldRoot,
		HeadNewRoot:     p.HeadNewRoot,
		Member:          p.Member,
		Genesis:         p.Genesis,
		NewIndex:        p.NewIndex,
		LowMember:       p.LowMember,
		LowNext:         p.LowNext,
		LowNullifier:    p.LowNullifier,
		LowIndex:        p.LowIndex,
	}
	for i := range circuit.LowProof {
		circuit.LowProof[i] = p.LowProof[i]
		circuit.NewProof[i] = p.NewProof[i]
	}
	return circuit, nil
}

func ProveCompressedRegister(ps *common.RingProofSystem, params *CompressedRegisterParameters) (*common.Proof, error) {
	assignment, err := params.CreateWitness()
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
