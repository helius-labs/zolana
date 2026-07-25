package merge

import (
	"encoding/json"
	"math/big"

	"zolana/prover/prover/common"
)

type InputParamsJSON struct {
	Domain                   string   `json:"domain"`
	Amount                   string   `json:"amount"`
	Blinding                 string   `json:"blinding"`
	ZoneDataHash             string   `json:"zoneDataHash"`
	StatePathElements        []string `json:"statePathElements"`
	StatePathIndex           string   `json:"statePathIndex"`
	NullifierLowValue        string   `json:"nullifierLowValue"`
	NullifierNextValue       string   `json:"nullifierNextValue"`
	NullifierLowPathElements []string `json:"nullifierLowPathElements"`
	NullifierLowPathIndex    string   `json:"nullifierLowPathIndex"`
	UtxoTreeRoot             string   `json:"utxoTreeRoot"`
	NullifierTreeRoot        string   `json:"nullifierTreeRoot"`
	Nullifier                string   `json:"nullifier"`
}

type OutputParamsJSON struct {
	Blinding     string `json:"blinding"`
	ZoneDataHash string `json:"zoneDataHash"`
	Hash         string `json:"hash"`
}

type MergeParametersJSON struct {
	CircuitType         common.CircuitType `json:"circuitType"`
	Inputs              []InputParamsJSON  `json:"inputs"`
	Output              OutputParamsJSON   `json:"output"`
	Asset               string             `json:"asset"`
	P256PubX            string             `json:"p256PubX"`
	P256PubY            string             `json:"p256PubY"`
	OwnerPkHash         string             `json:"ownerPkHash"`
	UserNullifierPk     string             `json:"userNullifierPk"`
	UserNullifierSecret string             `json:"userNullifierSecret"`
	TxViewingSk         string             `json:"txViewingSk"`
	UserViewingPubkey   []string           `json:"userViewingPubkey"`
	TxViewingPkLo       string             `json:"txViewingPkLo"`
	TxViewingPkHi       string             `json:"txViewingPkHi"`
	CtHash              string             `json:"ctHash"`
	UserViewingPkHash   string             `json:"userViewingPkHash"`
	ExternalDataHash    string             `json:"externalDataHash"`
	PrivateTxHash       string             `json:"privateTxHash"`
	PublicInputHash     string             `json:"publicInputHash"`
	// ZoneProgramID is the policy-zone merge circuit's top-level public input
	// (the zone program's pk_field). Emitted/consumed only on the merge-zone rail;
	// the default merge rail leaves it zero.
	ZoneProgramID string `json:"zoneProgramId"`
}

func (p *MergeParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.CreateMergeParametersJSON())
}

func (p *MergeParameters) UnmarshalJSON(data []byte) error {
	var params MergeParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	return p.UpdateWithJSON(params)
}

func (p *MergeParameters) CreateMergeParametersJSON() MergeParametersJSON {
	circuitType := p.CircuitType
	if circuitType == "" {
		circuitType = common.MergeCircuitType
	}
	paramsJson := MergeParametersJSON{
		CircuitType:         circuitType,
		Asset:               feHex(p.Asset),
		ZoneProgramID:       feHex(p.ZoneProgramID),
		P256PubX:            feHex(p.P256PubX),
		P256PubY:            feHex(p.P256PubY),
		OwnerPkHash:         feHex(p.OwnerPkHash),
		UserNullifierPk:     feHex(p.UserNullifierPk),
		UserNullifierSecret: feHex(p.UserNullifierSecret),
		TxViewingSk:         feHex(p.TxViewingSk),
		UserViewingPubkey:   feHexSlice(p.UserViewingPubkey),
		TxViewingPkLo:       feHex(p.TxViewingPkLo),
		TxViewingPkHi:       feHex(p.TxViewingPkHi),
		CtHash:              feHex(p.CtHash),
		UserViewingPkHash:   feHex(p.UserViewingPkHash),
		ExternalDataHash:    feHex(p.ExternalDataHash),
		PrivateTxHash:       feHex(p.PrivateTxHash),
		PublicInputHash:     feHex(p.PublicInputHash),
	}

	paramsJson.Inputs = make([]InputParamsJSON, len(p.Inputs))
	for i, in := range p.Inputs {
		paramsJson.Inputs[i] = InputParamsJSON{
			Domain:                   feHex(in.Domain),
			Amount:                   feHex(in.Amount),
			Blinding:                 feHex(in.Blinding),
			ZoneDataHash:             feHex(in.ZoneDataHash),
			StatePathElements:        feHexSlice(in.StatePathElements),
			StatePathIndex:           feHex(in.StatePathIndex),
			NullifierLowValue:        feHex(in.NullifierLowValue),
			NullifierNextValue:       feHex(in.NullifierNextValue),
			NullifierLowPathElements: feHexSlice(in.NullifierLowPathElements),
			NullifierLowPathIndex:    feHex(in.NullifierLowPathIndex),
			UtxoTreeRoot:             feHex(in.UtxoTreeRoot),
			NullifierTreeRoot:        feHex(in.NullifierTreeRoot),
			Nullifier:                feHex(in.Nullifier),
		}
	}

	paramsJson.Output = OutputParamsJSON{
		Blinding:     feHex(p.Output.Blinding),
		ZoneDataHash: feHex(p.Output.ZoneDataHash),
		Hash:         feHex(p.Output.Hash),
	}

	return paramsJson
}

func (p *MergeParameters) UpdateWithJSON(params MergeParametersJSON) error {
	var err error
	p.CircuitType = params.CircuitType
	if p.CircuitType == "" {
		p.CircuitType = common.MergeCircuitType
	}
	if p.ZoneProgramID, err = feFromHex(params.ZoneProgramID); err != nil {
		return err
	}
	if p.P256PubX, err = feFromHex(params.P256PubX); err != nil {
		return err
	}
	if p.P256PubY, err = feFromHex(params.P256PubY); err != nil {
		return err
	}
	if p.OwnerPkHash, err = feFromHex(params.OwnerPkHash); err != nil {
		return err
	}
	if p.UserNullifierPk, err = feFromHex(params.UserNullifierPk); err != nil {
		return err
	}
	if p.UserNullifierSecret, err = feFromHex(params.UserNullifierSecret); err != nil {
		return err
	}
	if p.TxViewingSk, err = feFromHex(params.TxViewingSk); err != nil {
		return err
	}
	if p.UserViewingPubkey, err = feFromHexSlice(params.UserViewingPubkey); err != nil {
		return err
	}
	if p.TxViewingPkLo, err = feFromHex(params.TxViewingPkLo); err != nil {
		return err
	}
	if p.TxViewingPkHi, err = feFromHex(params.TxViewingPkHi); err != nil {
		return err
	}
	if p.CtHash, err = feFromHex(params.CtHash); err != nil {
		return err
	}
	if p.UserViewingPkHash, err = feFromHex(params.UserViewingPkHash); err != nil {
		return err
	}
	if p.ExternalDataHash, err = feFromHex(params.ExternalDataHash); err != nil {
		return err
	}
	if p.PrivateTxHash, err = feFromHex(params.PrivateTxHash); err != nil {
		return err
	}
	if p.PublicInputHash, err = feFromHex(params.PublicInputHash); err != nil {
		return err
	}
	if p.Asset, err = feFromHex(params.Asset); err != nil {
		return err
	}

	p.Inputs = make([]InputParams, len(params.Inputs))
	for i, in := range params.Inputs {
		input := InputParams{}
		if input.Domain, err = feFromHex(in.Domain); err != nil {
			return err
		}
		if input.Amount, err = feFromHex(in.Amount); err != nil {
			return err
		}
		if input.Blinding, err = feFromHex(in.Blinding); err != nil {
			return err
		}
		if input.ZoneDataHash, err = feFromHex(in.ZoneDataHash); err != nil {
			return err
		}
		if input.StatePathElements, err = feFromHexSlice(in.StatePathElements); err != nil {
			return err
		}
		if input.StatePathIndex, err = feFromHex(in.StatePathIndex); err != nil {
			return err
		}
		if input.NullifierLowValue, err = feFromHex(in.NullifierLowValue); err != nil {
			return err
		}
		if input.NullifierNextValue, err = feFromHex(in.NullifierNextValue); err != nil {
			return err
		}
		if input.NullifierLowPathElements, err = feFromHexSlice(in.NullifierLowPathElements); err != nil {
			return err
		}
		if input.NullifierLowPathIndex, err = feFromHex(in.NullifierLowPathIndex); err != nil {
			return err
		}
		if input.UtxoTreeRoot, err = feFromHex(in.UtxoTreeRoot); err != nil {
			return err
		}
		if input.NullifierTreeRoot, err = feFromHex(in.NullifierTreeRoot); err != nil {
			return err
		}
		if input.Nullifier, err = feFromHex(in.Nullifier); err != nil {
			return err
		}
		p.Inputs[i] = input
	}

	output := OutputParams{}
	if output.Blinding, err = feFromHex(params.Output.Blinding); err != nil {
		return err
	}
	if output.ZoneDataHash, err = feFromHex(params.Output.ZoneDataHash); err != nil {
		return err
	}
	if output.Hash, err = feFromHex(params.Output.Hash); err != nil {
		return err
	}
	p.Output = output

	return nil
}

func feHex(i *big.Int) string {
	if i == nil {
		return common.ToHex(big.NewInt(0))
	}
	return common.ToHex(i)
}

func feHexSlice(xs []*big.Int) []string {
	out := make([]string, len(xs))
	for i := range xs {
		out[i] = feHex(xs[i])
	}
	return out
}

func feFromHex(s string) (*big.Int, error) {
	v := new(big.Int)
	if s == "" {
		return v, nil
	}
	if err := common.FromHex(v, s); err != nil {
		return nil, err
	}
	return v, nil
}

func feFromHexSlice(ss []string) ([]*big.Int, error) {
	out := make([]*big.Int, len(ss))
	for i, s := range ss {
		v, err := feFromHex(s)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
