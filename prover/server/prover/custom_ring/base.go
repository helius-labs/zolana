package custom_ring

import (
	"encoding/json"
	"fmt"
	"math/big"

	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// BaseParameters is the audit statement witness, the prefix of the folded
// PolicyParameters.
type BaseParameters struct {
	PublicInputHash      *big.Int
	PrivateTxHash        *big.Int
	Anonymous            bool
	TxViewingSk          [scalarLen]byte
	EphSk                [scalarLen]byte
	AuditorPk            [32]byte
	Salt                 [16]byte
	NOut                 uint8
	Outputs              [base.AuditOutputSlots]AuditOpening
	Sender               [identityLen]byte
	NIn                  uint8
	Inputs               [base.AuditInputSlots]Opening
	AnonymousOutputs     [base.AuditOutputSlots]Opening
	Recipients           [base.AuditOutputSlots][identityLen]byte
	RecipientViewingKeys [base.AuditOutputSlots][33]byte
	PrivateTxBlinding    *big.Int
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
	CircuitType          string             `json:"circuitType"`
	PublicInputHash      string             `json:"publicInputHash"`
	PrivateTxHash        string             `json:"privateTxHash"`
	Anonymous            bool               `json:"anonymous,omitempty"`
	TxViewingSk          string             `json:"txViewingSk"`
	EphSk                string             `json:"ephSk"`
	AuditorPk            string             `json:"auditorPk"`
	Salt                 string             `json:"salt"`
	NOut                 uint8              `json:"nOut"`
	Outputs              []auditOpeningJSON `json:"outputs"`
	Sender               string             `json:"sender,omitempty"`
	NIn                  uint8              `json:"nIn,omitempty"`
	Inputs               []openingJSON      `json:"inputs,omitempty"`
	AnonymousOutputs     []openingJSON      `json:"anonymousOutputs,omitempty"`
	Recipients           []string           `json:"recipients,omitempty"`
	RecipientViewingKeys []string           `json:"recipientViewingKeys,omitempty"`
	PrivateTxBlinding    string             `json:"privateTxBlinding,omitempty"`
}

func (p *BaseParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(baseParametersJSON{
		CircuitType:          string(common.CustomRingBaseCircuitType),
		PublicInputHash:      common.ToHex(p.PublicInputHash),
		PrivateTxHash:        common.ToHex(p.PrivateTxHash),
		Anonymous:            p.Anonymous,
		TxViewingSk:          bytesHex(p.TxViewingSk[:]),
		EphSk:                bytesHex(p.EphSk[:]),
		AuditorPk:            bytesHex(p.AuditorPk[:]),
		Salt:                 bytesHex(p.Salt[:]),
		NOut:                 p.NOut,
		Outputs:              writeAuditOpenings(p.Outputs[:]),
		Sender:               identityHex(p.Sender, p.Anonymous),
		NIn:                  p.NIn,
		Inputs:               writeAnonymousOpenings(p.Inputs[:], p.Anonymous),
		AnonymousOutputs:     writeAnonymousOpenings(p.AnonymousOutputs[:], p.Anonymous),
		Recipients:           writeIdentities(p.Recipients[:], p.Anonymous),
		RecipientViewingKeys: writeViewingKeys(p.RecipientViewingKeys[:], p.Anonymous),
		PrivateTxBlinding:    anonymousFieldHex(p.PrivateTxBlinding, p.Anonymous),
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
	if err = bytesFromHex(p.AuditorPk[:], raw.AuditorPk, "auditorPk"); err != nil {
		return err
	}
	if err := validateX25519Point(p.AuditorPk[:], "auditorPk"); err != nil {
		return err
	}
	if err = bytesFromHex(p.Salt[:], raw.Salt, "salt"); err != nil {
		return err
	}
	if raw.NOut == 0 || int(raw.NOut) > base.AuditOutputSlots {
		return fmt.Errorf("custom-ring: nOut %d is outside 1..%d", raw.NOut, base.AuditOutputSlots)
	}
	if raw.Anonymous != (raw.NIn != 0) || int(raw.NIn) > base.AuditInputSlots {
		return fmt.Errorf("custom-ring: nIn %d does not match anonymous %t", raw.NIn, raw.Anonymous)
	}
	if len(raw.Outputs) != base.AuditOutputSlots {
		return fmt.Errorf("custom-ring: outputs has %d entries, expected %d", len(raw.Outputs), base.AuditOutputSlots)
	}
	p.NOut, p.NIn, p.Anonymous = raw.NOut, raw.NIn, raw.Anonymous
	for i := range p.Outputs {
		if err = readAuditOpening(&p.Outputs[i], raw.Outputs[i], fmt.Sprintf("outputs[%d]", i)); err != nil {
			return err
		}
	}
	if err = readSender(p.Sender[:], raw.Sender, raw.Anonymous); err != nil {
		return err
	}
	if err = readIdentities(p.Recipients[:], raw.Recipients, raw.Anonymous); err != nil {
		return err
	}
	if err = readViewingKeys(p.RecipientViewingKeys[:], raw.RecipientViewingKeys, raw.Anonymous); err != nil {
		return err
	}
	if raw.Anonymous {
		if p.PrivateTxBlinding, err = fieldFromHex(raw.PrivateTxBlinding, "privateTxBlinding"); err != nil {
			return err
		}
		if err = readOpenings(p.Inputs[:], raw.Inputs, "inputs"); err != nil {
			return err
		}
		if err = readOpenings(p.AnonymousOutputs[:], raw.AnonymousOutputs, "anonymousOutputs"); err != nil {
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
		PublicInputHash:   p.PublicInputHash,
		PrivateTxHash:     p.PrivateTxHash,
		Anonymous:         boolVar(p.Anonymous),
		Sender:            identityWires(p.Sender),
		PrivateTxBlinding: 0,
	}
	if p.Anonymous {
		circuit.PrivateTxBlinding = p.PrivateTxBlinding
	}
	assignBytes(circuit.TxViewingSk[:], p.TxViewingSk[:])
	assignBytes(circuit.EphSk[:], p.EphSk[:])
	assignBytes(circuit.AuditorPk[:], p.AuditorPk[:])
	assignBytes(circuit.Salt[:], p.Salt[:])
	for i := range circuit.Outputs {
		assignAuditOpening(&circuit.Outputs[i], &p.Outputs[i])
		circuit.AnonymousOutputs[i] = base.ZeroAuditUtxo()
		if p.Anonymous {
			assignAnonymousOpening(&circuit.AnonymousOutputs[i], &p.AnonymousOutputs[i])
		}
		circuit.Recipients[i] = identityWires(p.Recipients[i])
		assignBytes(circuit.Recipients[i].ViewingPk[:], p.RecipientViewingKeys[i][:])
	}
	for i := range circuit.Inputs {
		circuit.Inputs[i] = base.ZeroAuditUtxo()
		if p.Anonymous {
			assignAnonymousOpening(&circuit.Inputs[i], &p.Inputs[i])
		}
	}
	assignOneHot(circuit.InputCountSelected[:], int(p.NIn))
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

func assignAnonymousOpening(out *base.AuditUtxoWires, opening *Opening) {
	out.Domain, out.TreeID = opening.Domain, opening.TreeID
	out.OwnerPkHash, out.NullifierPk = opening.OwnerPkHash, opening.NullifierPk
	out.Asset, out.Amount, out.Blinding = opening.Asset, opening.Amount, opening.Blinding
	out.DataHash, out.RingDataHash, out.RingProgramID = opening.DataHash, opening.RingDataHash, opening.RingProgramID
}

func writeAnonymousOpenings(openings []Opening, anonymous bool) []openingJSON {
	if !anonymous {
		return nil
	}
	return writeOpenings(openings)
}

func anonymousFieldHex(value *big.Int, anonymous bool) string {
	if anonymous {
		return common.ToHex(value)
	}
	return ""
}
