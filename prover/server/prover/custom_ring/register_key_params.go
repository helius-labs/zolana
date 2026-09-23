package custom_ring

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/custom_rings/circuits/policy"
	"zolana/prover/prover/common"
)

type KeyRegisterParameters struct {
	PublicInputHash *big.Int
	registryInsertion
	NullifierSecret [scalarLen]byte
	EphSk           [scalarLen]byte
	AuditorPk       [uncompressedPubkeyLen]byte
}

type keyRegisterParametersJSON struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash string `json:"publicInputHash"`
	registryInsertionJSON
	NullifierSecret string `json:"nullifierSecret"`
	EphSk           string `json:"ephSk"`
	AuditorPk       string `json:"auditorPk"`
}

func (p *KeyRegisterParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(keyRegisterParametersJSON{
		CircuitType:           string(common.CustomRingKeyRegisterCircuitType),
		PublicInputHash:       common.ToHex(p.PublicInputHash),
		registryInsertionJSON: p.registryInsertion.json(),
		NullifierSecret:       bytesHex(p.NullifierSecret[:]),
		EphSk:                 bytesHex(p.EphSk[:]),
		AuditorPk:             bytesHex(p.AuditorPk[:]),
	})
}

func (p *KeyRegisterParameters) UnmarshalJSON(data []byte) error {
	var raw keyRegisterParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	rail := string(common.CustomRingKeyRegisterCircuitType)
	if raw.CircuitType != rail {
		return fmt.Errorf("%s: unexpected circuitType %q", rail, raw.CircuitType)
	}
	var err error
	if p.PublicInputHash, err = fieldFromHex(raw.PublicInputHash, "publicInputHash"); err != nil {
		return err
	}
	if err := bytesFromHex(p.NullifierSecret[:], raw.NullifierSecret, "nullifierSecret"); err != nil {
		return err
	}
	// Byte 0 pinned to zero keeps the 31-byte secret below the field order.
	if p.NullifierSecret[0] != 0 {
		return fmt.Errorf("%s: nullifierSecret high byte is not zero", rail)
	}
	if err := bytesFromHex(p.EphSk[:], raw.EphSk, "ephSk"); err != nil {
		return err
	}
	if err := validateP256Scalar(p.EphSk[:], "ephSk"); err != nil {
		return err
	}
	if err := bytesFromHex(p.AuditorPk[:], raw.AuditorPk, "auditorPk"); err != nil {
		return err
	}
	if err := validateP256Point(p.AuditorPk[:], "auditorPk"); err != nil {
		return err
	}
	return p.registryInsertion.decode(raw.registryInsertionJSON, rail)
}

func (p *KeyRegisterParameters) CreateWitness() (*policy.KeyRegisterCircuit, error) {
	circuit := &policy.KeyRegisterCircuit{
		PublicInputHash: p.PublicInputHash,
		RegistryOldRoot: p.RegistryOldRoot,
		RegistryNewRoot: p.RegistryNewRoot,
		Member:          p.Member,
		NewIndex:        p.NewIndex,
		LowMember:       p.LowMember,
		LowNext:         p.LowNext,
		LowKey:          p.LowKey,
		LowIndex:        p.LowIndex,
	}
	assignBytes(circuit.NullifierSecret[:], p.NullifierSecret[:])
	assignBytes(circuit.EphSk[:], p.EphSk[:])
	assignBytes(circuit.AuditorPk[:], p.AuditorPk[:])
	for i := range circuit.LowProof {
		circuit.LowProof[i] = p.LowProof[i]
		circuit.NewProof[i] = p.NewProof[i]
	}
	return circuit, nil
}
