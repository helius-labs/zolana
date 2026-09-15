package custom_ring

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover/common"
)

type CompressedRegisterParameters struct {
	PublicInputHash *big.Int
	headInsertion
	Genesis *big.Int
}

type compressedRegisterParametersJSON struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash string `json:"publicInputHash"`
	headInsertionJSON
	Genesis string `json:"genesis"`
}

func (p *CompressedRegisterParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(compressedRegisterParametersJSON{
		CircuitType:       string(common.CustomRingCompressedRegisterCircuitType),
		PublicInputHash:   common.ToHex(p.PublicInputHash),
		headInsertionJSON: p.headInsertion.json(),
		Genesis:           common.ToHex(p.Genesis),
	})
}

func (p *CompressedRegisterParameters) UnmarshalJSON(data []byte) error {
	var raw compressedRegisterParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	rail := string(common.CustomRingCompressedRegisterCircuitType)
	if raw.CircuitType != rail {
		return fmt.Errorf("%s: unexpected circuitType %q", rail, raw.CircuitType)
	}
	var err error
	if p.PublicInputHash, err = fieldFromHex(raw.PublicInputHash, "publicInputHash"); err != nil {
		return err
	}
	if p.Genesis, err = fieldFromHex(raw.Genesis, "genesis"); err != nil {
		return err
	}
	return p.headInsertion.decode(raw.headInsertionJSON, rail)
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
