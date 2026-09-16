package custom_ring

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"

	base "zolana/prover/circuits/custom_ring/base"
	"zolana/prover/prover/common"
)

// BaseParameters is the audit statement witness, the prefix of the folded
// PolicyParameters.
type BaseParameters struct {
	PublicInputHash *big.Int
	PrivateTxHash   *big.Int
	TxViewingSk     [scalarLen]byte
	EphSk           [scalarLen]byte
	AuditorPk       [uncompressedPubkeyLen]byte
}

type baseParametersJSON struct {
	CircuitType     string `json:"circuitType"`
	PublicInputHash string `json:"publicInputHash"`
	PrivateTxHash   string `json:"privateTxHash"`
	TxViewingSk     string `json:"txViewingSk"`
	EphSk           string `json:"ephSk"`
	AuditorPk       string `json:"auditorPk"`
}

func (p *BaseParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(baseParametersJSON{
		CircuitType:     string(common.CustomRingBaseCircuitType),
		PublicInputHash: common.ToHex(p.PublicInputHash),
		PrivateTxHash:   common.ToHex(p.PrivateTxHash),
		TxViewingSk:     bytesHex(p.TxViewingSk[:]),
		EphSk:           bytesHex(p.EphSk[:]),
		AuditorPk:       bytesHex(p.AuditorPk[:]),
	})
}

func (p *BaseParameters) UnmarshalJSON(data []byte) error {
	var raw baseParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.CustomRingBaseCircuitType) {
		return fmt.Errorf("custom-ring-base: unexpected circuitType %q", raw.CircuitType)
	}
	var err error
	if p.PublicInputHash, err = fieldFromHex(raw.PublicInputHash, "publicInputHash"); err != nil {
		return err
	}
	if p.PrivateTxHash, err = fieldFromHex(raw.PrivateTxHash, "privateTxHash"); err != nil {
		return err
	}
	if err = bytesFromHex(p.TxViewingSk[:], raw.TxViewingSk, "txViewingSk"); err != nil {
		return err
	}
	if err = validateP256Scalar(p.TxViewingSk[:], "txViewingSk"); err != nil {
		return err
	}
	if err = bytesFromHex(p.EphSk[:], raw.EphSk, "ephSk"); err != nil {
		return err
	}
	if err = validateP256Scalar(p.EphSk[:], "ephSk"); err != nil {
		return err
	}
	if err = bytesFromHex(p.AuditorPk[:], raw.AuditorPk, "auditorPk"); err != nil {
		return err
	}
	if x, y := elliptic.Unmarshal(elliptic.P256(), p.AuditorPk[:]); x == nil || y == nil {
		return fmt.Errorf("custom-ring: auditorPk is not a P256 point")
	}
	return nil
}

func (p *BaseParameters) CreateWitness() (*base.CustomRingBaseCircuit, error) {
	if p.PublicInputHash == nil || p.PrivateTxHash == nil {
		return nil, fmt.Errorf("custom-ring: missing hash")
	}
	circuit := &base.CustomRingBaseCircuit{
		PublicInputHash: p.PublicInputHash,
		PrivateTxHash:   p.PrivateTxHash,
	}
	assignBytes(circuit.TxViewingSk[:], p.TxViewingSk[:])
	assignBytes(circuit.EphSk[:], p.EphSk[:])
	assignBytes(circuit.AuditorPk[:], p.AuditorPk[:])
	return circuit, nil
}
