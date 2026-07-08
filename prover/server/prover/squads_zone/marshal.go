package squadszone

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/prover/common"
)

type UtxoParamsJSON struct {
	OwnerHash       string `json:"ownerHash"`
	Asset           string `json:"asset"`
	Amount          string `json:"amount"`
	Blinding        string `json:"blinding"`
	ProgramDataHash string `json:"programDataHash"`
	ZoneDataHash    string `json:"zoneDataHash"`
	ZoneProgramID   string `json:"zoneProgramId"`
}

type SenderParamsJSON struct {
	Owner                            string `json:"owner"`
	SharedViewingSecretKeyCommitment string `json:"sharedViewingSecretKeyCommitment"`
	NullifierPubkey                  string `json:"nullifierPubkey"`
	NullifierSecret                  string `json:"nullifierSecret"`
	SharedViewingSecretKey           string `json:"sharedViewingSecretKey"`
}

type RecipientParamsJSON struct {
	Owner           string   `json:"owner"`
	NullifierPubkey string   `json:"nullifierPubkey"`
	ViewingPubkey   []string `json:"viewingPubkey"`
}

type ProposalParamsJSON struct {
	Amount       string `json:"amount"`
	Recipient    string `json:"recipient"`
	Blinding     string `json:"blinding"`
	PublicAmount string `json:"publicAmount"`
}

type ZoneParametersJSON struct {
	CircuitType        common.CircuitType  `json:"circuitType"`
	NInputs            uint32              `json:"nInputs"`
	NOutputs           uint32              `json:"nOutputs"`
	Inputs             []UtxoParamsJSON    `json:"inputs"`
	InputsDummy        []string            `json:"inputsDummy,omitempty"`
	Outputs            []UtxoParamsJSON    `json:"outputs"`
	ExternalDataHash   string              `json:"externalDataHash"`
	Sender             SenderParamsJSON    `json:"sender"`
	Recipient          RecipientParamsJSON `json:"recipient"`
	Proposal           ProposalParamsJSON  `json:"proposal"`
	EnableProposalHash string              `json:"enableProposalHash"`
	PublicAmount       string              `json:"publicAmount"`
	PublicInputHash    string              `json:"publicInputHash"`
}

func (p *ZoneParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.toJSON())
}

func (p *ZoneParameters) UnmarshalJSON(data []byte) error {
	var params ZoneParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	return p.updateWithJSON(params)
}

func (p *ZoneParameters) toJSON() ZoneParametersJSON {
	out := ZoneParametersJSON{
		CircuitType:      common.SquadsZoneCircuitType,
		NInputs:          p.NInputs,
		NOutputs:         p.NOutputs,
		ExternalDataHash: common.FeHex(p.ExternalDataHash),
		Sender: SenderParamsJSON{
			Owner:                            common.FeHex(p.Sender.Owner),
			SharedViewingSecretKeyCommitment: common.FeHex(p.Sender.SharedViewingSecretKeyCommitment),
			NullifierPubkey:                  common.FeHex(p.Sender.NullifierPubkey),
			NullifierSecret:                  common.FeHex(p.Sender.NullifierSecret),
			SharedViewingSecretKey:           common.FeHex(p.Sender.SharedViewingSecretKey),
		},
		Recipient: RecipientParamsJSON{
			Owner:           common.FeHex(p.Recipient.Owner),
			NullifierPubkey: common.FeHex(p.Recipient.NullifierPubkey),
			ViewingPubkey:   common.FeHexSlice(p.Recipient.ViewingPubkey[:]),
		},
		Proposal: ProposalParamsJSON{
			Amount:       common.FeHex(p.Proposal.Amount),
			Recipient:    common.FeHex(p.Proposal.Recipient),
			Blinding:     common.FeHex(p.Proposal.Blinding),
			PublicAmount: common.FeHex(p.Proposal.PublicAmount),
		},
		EnableProposalHash: common.FeHex(p.EnableProposalHash),
		PublicAmount:       common.FeHex(p.PublicAmount),
		PublicInputHash:    common.FeHex(p.PublicInputHash),
	}

	out.Inputs = make([]UtxoParamsJSON, len(p.Inputs))
	for i, u := range p.Inputs {
		out.Inputs[i] = utxoParamsToJSON(u)
	}
	if len(p.InputsDummy) > 0 {
		out.InputsDummy = common.FeHexSlice(p.InputsDummy)
	}
	out.Outputs = make([]UtxoParamsJSON, len(p.Outputs))
	for i, u := range p.Outputs {
		out.Outputs[i] = utxoParamsToJSON(u)
	}
	return out
}

func (p *ZoneParameters) updateWithJSON(params ZoneParametersJSON) error {
	var err error
	p.NInputs = params.NInputs
	p.NOutputs = params.NOutputs

	if p.ExternalDataHash, err = common.FeFromHex(params.ExternalDataHash); err != nil {
		return err
	}
	if p.Sender.Owner, err = common.FeFromHex(params.Sender.Owner); err != nil {
		return err
	}
	if p.Sender.SharedViewingSecretKeyCommitment, err = common.FeFromHex(params.Sender.SharedViewingSecretKeyCommitment); err != nil {
		return err
	}
	if p.Sender.NullifierPubkey, err = common.FeFromHex(params.Sender.NullifierPubkey); err != nil {
		return err
	}
	if p.Sender.NullifierSecret, err = common.FeFromHex(params.Sender.NullifierSecret); err != nil {
		return err
	}
	if p.Sender.SharedViewingSecretKey, err = common.FeFromHex(params.Sender.SharedViewingSecretKey); err != nil {
		return err
	}
	if p.Recipient.Owner, err = common.FeFromHex(params.Recipient.Owner); err != nil {
		return err
	}
	if p.Recipient.NullifierPubkey, err = common.FeFromHex(params.Recipient.NullifierPubkey); err != nil {
		return err
	}
	pk, err := common.FeFromHexSlice(params.Recipient.ViewingPubkey)
	if err != nil {
		return err
	}
	if len(pk) != 65 {
		return fmt.Errorf("recipient viewingPubkey must be 65 bytes, got %d", len(pk))
	}
	for i := 0; i < 65; i++ {
		p.Recipient.ViewingPubkey[i] = pk[i]
	}
	if p.Proposal.Amount, err = common.FeFromHex(params.Proposal.Amount); err != nil {
		return err
	}
	if p.Proposal.Recipient, err = common.FeFromHex(params.Proposal.Recipient); err != nil {
		return err
	}
	if p.Proposal.Blinding, err = common.FeFromHex(params.Proposal.Blinding); err != nil {
		return err
	}
	if p.Proposal.PublicAmount, err = common.FeFromHex(params.Proposal.PublicAmount); err != nil {
		return err
	}
	if p.EnableProposalHash, err = common.FeFromHex(params.EnableProposalHash); err != nil {
		return err
	}
	if p.PublicAmount, err = common.FeFromHex(params.PublicAmount); err != nil {
		return err
	}
	if p.PublicInputHash, err = common.FeFromHex(params.PublicInputHash); err != nil {
		return err
	}

	p.Inputs = make([]UtxoParams, len(params.Inputs))
	for i, u := range params.Inputs {
		if p.Inputs[i], err = utxoParamsFromJSON(u); err != nil {
			return err
		}
	}
	dummyLen := 0
	if params.NInputs > 0 {
		dummyLen = int(params.NInputs) - 1
	}
	if len(params.InputsDummy) == 0 {
		p.InputsDummy = make([]*big.Int, dummyLen)
		for i := range p.InputsDummy {
			p.InputsDummy[i] = new(big.Int)
		}
	} else {
		if len(params.InputsDummy) != dummyLen {
			return fmt.Errorf("inputsDummy must have nInputs-1 = %d entries, got %d", dummyLen, len(params.InputsDummy))
		}
		if p.InputsDummy, err = common.FeFromHexSlice(params.InputsDummy); err != nil {
			return err
		}
	}
	p.Outputs = make([]UtxoParams, len(params.Outputs))
	for i, u := range params.Outputs {
		if p.Outputs[i], err = utxoParamsFromJSON(u); err != nil {
			return err
		}
	}
	return nil
}

func utxoParamsToJSON(u UtxoParams) UtxoParamsJSON {
	return UtxoParamsJSON{
		OwnerHash:       common.FeHex(u.OwnerHash),
		Asset:           common.FeHex(u.Asset),
		Amount:          common.FeHex(u.Amount),
		Blinding:        common.FeHex(u.Blinding),
		ProgramDataHash: common.FeHex(u.ProgramDataHash),
		ZoneDataHash:    common.FeHex(u.ZoneDataHash),
		ZoneProgramID:   common.FeHex(u.ZoneProgramID),
	}
}

func utxoParamsFromJSON(u UtxoParamsJSON) (UtxoParams, error) {
	var out UtxoParams
	var err error
	if out.OwnerHash, err = common.FeFromHex(u.OwnerHash); err != nil {
		return out, err
	}
	if out.Asset, err = common.FeFromHex(u.Asset); err != nil {
		return out, err
	}
	if out.Amount, err = common.FeFromHex(u.Amount); err != nil {
		return out, err
	}
	if out.Blinding, err = common.FeFromHex(u.Blinding); err != nil {
		return out, err
	}
	if out.ProgramDataHash, err = common.FeFromHex(u.ProgramDataHash); err != nil {
		return out, err
	}
	if out.ZoneDataHash, err = common.FeFromHex(u.ZoneDataHash); err != nil {
		return out, err
	}
	if out.ZoneProgramID, err = common.FeFromHex(u.ZoneProgramID); err != nil {
		return out, err
	}
	return out, nil
}
