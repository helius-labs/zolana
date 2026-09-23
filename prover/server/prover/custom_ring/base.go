package custom_ring

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"

	base "zolana/prover/custom_rings/circuits/base"
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
	Salt            [16]byte
	NOut            uint8
	Outputs         [base.AuditOutputSlots]AuditOpening
}

type AuditOpening struct {
	Domain        *big.Int
	TreeID        *big.Int
	OwnerHash     *big.Int
	Asset         *big.Int
	Amount        *big.Int
	Blinding      *big.Int
	DataHash      *big.Int
	RingDataHash  *big.Int
	RingProgramID *big.Int
}

type auditOpeningJSON struct {
	Domain        string `json:"domain"`
	TreeID        string `json:"treeId"`
	OwnerHash     string `json:"ownerHash"`
	Asset         string `json:"asset"`
	Amount        string `json:"amount"`
	Blinding      string `json:"blinding"`
	DataHash      string `json:"dataHash"`
	RingDataHash  string `json:"ringDataHash"`
	RingProgramID string `json:"ringProgramId"`
}

type baseParametersJSON struct {
	CircuitType     string             `json:"circuitType"`
	PublicInputHash string             `json:"publicInputHash"`
	PrivateTxHash   string             `json:"privateTxHash"`
	TxViewingSk     string             `json:"txViewingSk"`
	EphSk           string             `json:"ephSk"`
	AuditorPk       string             `json:"auditorPk"`
	Salt            string             `json:"salt"`
	NOut            uint8              `json:"nOut"`
	Outputs         []auditOpeningJSON `json:"outputs"`
}

func (p *BaseParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(baseParametersJSON{
		CircuitType:     string(common.CustomRingBaseCircuitType),
		PublicInputHash: common.ToHex(p.PublicInputHash),
		PrivateTxHash:   common.ToHex(p.PrivateTxHash),
		TxViewingSk:     bytesHex(p.TxViewingSk[:]),
		EphSk:           bytesHex(p.EphSk[:]),
		AuditorPk:       bytesHex(p.AuditorPk[:]),
		Salt:            bytesHex(p.Salt[:]),
		NOut:            p.NOut,
		Outputs:         writeAuditOpenings(p.Outputs[:]),
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
	if err = bytesFromHex(p.Salt[:], raw.Salt, "salt"); err != nil {
		return err
	}
	if raw.NOut == 0 || int(raw.NOut) > base.AuditOutputSlots {
		return fmt.Errorf("custom-ring: nOut %d is outside 1..%d", raw.NOut, base.AuditOutputSlots)
	}
	if len(raw.Outputs) != base.AuditOutputSlots {
		return fmt.Errorf("custom-ring: outputs has %d entries, expected %d", len(raw.Outputs), base.AuditOutputSlots)
	}
	p.NOut = raw.NOut
	for i := range p.Outputs {
		if err = readAuditOpening(&p.Outputs[i], raw.Outputs[i], fmt.Sprintf("outputs[%d]", i)); err != nil {
			return err
		}
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
	assignBytes(circuit.Salt[:], p.Salt[:])
	for i := range circuit.Outputs {
		assignAuditOpening(&circuit.Outputs[i], &p.Outputs[i])
	}
	assignOneHot(circuit.OutputCountSelected[:], int(p.NOut)-1)
	return circuit, nil
}

func writeAuditOpenings(openings []AuditOpening) []auditOpeningJSON {
	out := make([]auditOpeningJSON, len(openings))
	for i, opening := range openings {
		out[i] = auditOpeningJSON{
			Domain: common.ToHex(opening.Domain), TreeID: common.ToHex(opening.TreeID),
			OwnerHash: common.ToHex(opening.OwnerHash), Asset: common.ToHex(opening.Asset),
			Amount: common.ToHex(opening.Amount), Blinding: common.ToHex(opening.Blinding),
			DataHash: common.ToHex(opening.DataHash), RingDataHash: common.ToHex(opening.RingDataHash),
			RingProgramID: common.ToHex(opening.RingProgramID),
		}
	}
	return out
}

func readAuditOpening(out *AuditOpening, raw auditOpeningJSON, name string) (err error) {
	fields := []struct {
		dst  **big.Int
		raw  string
		name string
	}{
		{&out.Domain, raw.Domain, "domain"}, {&out.TreeID, raw.TreeID, "treeId"},
		{&out.OwnerHash, raw.OwnerHash, "ownerHash"}, {&out.Asset, raw.Asset, "asset"},
		{&out.Amount, raw.Amount, "amount"}, {&out.Blinding, raw.Blinding, "blinding"},
		{&out.DataHash, raw.DataHash, "dataHash"}, {&out.RingDataHash, raw.RingDataHash, "ringDataHash"},
		{&out.RingProgramID, raw.RingProgramID, "ringProgramId"},
	}
	for _, field := range fields {
		*field.dst, err = fieldFromHex(field.raw, name+"."+field.name)
		if err != nil {
			return err
		}
	}
	return nil
}

func assignAuditOpening(out *base.AuditOutputWires, opening *AuditOpening) {
	out.Domain, out.TreeID, out.OwnerHash = opening.Domain, opening.TreeID, opening.OwnerHash
	out.Asset, out.Amount, out.Blinding = opening.Asset, opening.Amount, opening.Blinding
	out.DataHash, out.RingDataHash, out.RingProgramID = opening.DataHash, opening.RingDataHash, opening.RingProgramID
}
