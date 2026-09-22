package custom_ring

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/custom_rings/circuits/deposit"
	"zolana/prover/prover/common"
)

// DepositParameters binds a deposit batch to its auditor disclosure proof.
type DepositParameters struct {
	PublicInputHash *big.Int
	ContextHash     *big.Int
	Count           uint32
	OwnerHashes     [deposit.MaxDeposits]*big.Int
	Blindings       [deposit.MaxDeposits]*big.Int
	EphSk           [scalarLen]byte
	AuditorPk       [uncompressedPubkeyLen]byte
}

// The HTTP request preserves exact array lengths and canonical field encodings.
type depositParametersJSON struct {
	CircuitType     string   `json:"circuitType"`
	PublicInputHash string   `json:"publicInputHash"`
	ContextHash     string   `json:"contextHash"`
	Count           uint32   `json:"count"`
	OwnerHashes     []string `json:"ownerHashes"`
	Blindings       []string `json:"blindings"`
	EphSk           string   `json:"ephSk"`
	AuditorPk       string   `json:"auditorPk"`
}

func (p *DepositParameters) MarshalJSON() ([]byte, error) {
	owners, blindings := make([]string, deposit.MaxDeposits), make([]string, deposit.MaxDeposits)
	for i := range owners {
		owners[i], blindings[i] = common.ToHex(p.OwnerHashes[i]), common.ToHex(p.Blindings[i])
	}
	return json.Marshal(depositParametersJSON{
		CircuitType: string(common.CustomRingDepositCircuitType), PublicInputHash: common.ToHex(p.PublicInputHash),
		ContextHash: common.ToHex(p.ContextHash), Count: p.Count, OwnerHashes: owners, Blindings: blindings,
		EphSk: bytesHex(p.EphSk[:]), AuditorPk: bytesHex(p.AuditorPk[:]),
	})
}

func (p *DepositParameters) UnmarshalJSON(data []byte) error {
	var raw depositParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.CustomRingDepositCircuitType) {
		return fmt.Errorf("custom-ring-deposit: unexpected circuitType %q", raw.CircuitType)
	}
	if raw.Count < 1 || raw.Count > deposit.MaxDeposits || len(raw.OwnerHashes) != deposit.MaxDeposits || len(raw.Blindings) != deposit.MaxDeposits {
		return fmt.Errorf("custom-ring-deposit: invalid count or opening array length")
	}
	p.Count = raw.Count
	var err error
	if p.PublicInputHash, err = fieldFromHex(raw.PublicInputHash, "publicInputHash"); err != nil {
		return err
	}
	if p.ContextHash, err = fieldFromHex(raw.ContextHash, "contextHash"); err != nil {
		return err
	}
	for i := range p.OwnerHashes {
		if p.OwnerHashes[i], err = fieldFromHex(raw.OwnerHashes[i], "ownerHashes"); err != nil {
			return err
		}
		if p.Blindings[i], err = fieldFromHex(raw.Blindings[i], "blindings"); err != nil {
			return err
		}
		if i >= int(p.Count) && (p.OwnerHashes[i].Sign() != 0 || p.Blindings[i].Sign() != 0) {
			return fmt.Errorf("custom-ring-deposit: nonzero padding at slot %d", i)
		}
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
	return validateP256Point(p.AuditorPk[:], "auditorPk")
}

func (p *DepositParameters) CreateWitness() (*deposit.CustomRingDepositCircuit, error) {
	if p.PublicInputHash == nil || p.ContextHash == nil || p.Count < 1 || p.Count > deposit.MaxDeposits {
		return nil, fmt.Errorf("custom-ring-deposit: missing hashes or invalid count")
	}
	circuit := &deposit.CustomRingDepositCircuit{PublicInputHash: p.PublicInputHash, ContextHash: p.ContextHash, Count: p.Count}
	for i := range circuit.OwnerHashes {
		if p.OwnerHashes[i] == nil || p.Blindings[i] == nil {
			return nil, fmt.Errorf("custom-ring-deposit: missing opening at slot %d", i)
		}
		circuit.OwnerHashes[i], circuit.Blindings[i] = p.OwnerHashes[i], p.Blindings[i]
	}
	assignBytes(circuit.EphSk[:], p.EphSk[:])
	assignBytes(circuit.AuditorPk[:], p.AuditorPk[:])
	return circuit, nil
}
