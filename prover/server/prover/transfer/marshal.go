package transfer

import (
	"encoding/json"
	"math/big"

	"zolana/prover/prover/common"
)

type UtxoParamsJSON struct {
	Domain        string `json:"domain"`
	Owner         string `json:"owner"`
	Asset         string `json:"asset"`
	Amount        string `json:"amount"`
	Blinding      string `json:"blinding"`
	DataHash      string `json:"dataHash"`
	ZoneDataHash  string `json:"zoneDataHash"`
	ZoneProgramID string `json:"zoneProgramId"`
}

type InputParamsJSON struct {
	Utxo                     UtxoParamsJSON `json:"utxo"`
	IsDummy                  string         `json:"isDummy"`
	StatePathElements        []string       `json:"statePathElements"`
	StatePathIndex           string         `json:"statePathIndex"`
	NullifierLowValue        string         `json:"nullifierLowValue"`
	NullifierNextValue       string         `json:"nullifierNextValue"`
	NullifierLowPathElements []string       `json:"nullifierLowPathElements"`
	NullifierLowPathIndex    string         `json:"nullifierLowPathIndex"`
	UtxoTreeRoot             string         `json:"utxoTreeRoot"`
	NullifierTreeRoot        string         `json:"nullifierTreeRoot"`
	Nullifier                string         `json:"nullifier"`
	SolanaOwnerPkHash        string         `json:"solanaOwnerPkHash"`
	NullifierSecret          string         `json:"nullifierSecret"`
}

type OutputParamsJSON struct {
	Utxo    UtxoParamsJSON `json:"utxo"`
	IsDummy string         `json:"isDummy"`
	Hash    string         `json:"hash"`
}

type TransferParametersJSON struct {
	CircuitType          common.CircuitType `json:"circuitType"`
	NInputs              uint32             `json:"nInputs"`
	NOutputs             uint32             `json:"nOutputs"`
	Inputs               []InputParamsJSON  `json:"inputs"`
	Outputs              []OutputParamsJSON `json:"outputs"`
	ExternalDataHash     string             `json:"externalDataHash"`
	P256PubX             string             `json:"p256PubX"`
	P256PubY             string             `json:"p256PubY"`
	P256SigR             string             `json:"p256SigR"`
	P256SigS             string             `json:"p256SigS"`
	PrivateTxHash        string             `json:"privateTxHash"`
	P256MessageHash      string             `json:"p256MessageHash"`
	PublicSolAmount      string             `json:"publicSolAmount"`
	PublicSplAmount      string             `json:"publicSplAmount"`
	PublicSplAssetPubkey string             `json:"publicSplAssetPubkey"`
	ProgramIDHashchain   string             `json:"programIdHashchain"`
	PayerPubkeyHash      string             `json:"payerPubkeyHash"`
	DataHash             string             `json:"dataHash"`
	ZoneDataHash         string             `json:"zoneDataHash"`
	PublicInputHash      string             `json:"publicInputHash"`
}

func (p *TransferParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.CreateTransferParametersJSON())
}

func (p *TransferParameters) UnmarshalJSON(data []byte) error {
	var params TransferParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	return p.UpdateWithJSON(params)
}

func (p *TransferParameters) CreateTransferParametersJSON() TransferParametersJSON {
	paramsJson := TransferParametersJSON{
		CircuitType:          common.TransferCircuitType,
		NInputs:              p.NInputs,
		NOutputs:             p.NOutputs,
		ExternalDataHash:     feHex(p.ExternalDataHash),
		P256PubX:             feHex(p.P256PubX),
		P256PubY:             feHex(p.P256PubY),
		P256SigR:             feHex(p.P256SigR),
		P256SigS:             feHex(p.P256SigS),
		PrivateTxHash:        feHex(p.PrivateTxHash),
		P256MessageHash:      feHex(p.P256MessageHash),
		PublicSolAmount:      feHex(p.PublicSolAmount),
		PublicSplAmount:      feHex(p.PublicSplAmount),
		PublicSplAssetPubkey: feHex(p.PublicSplAssetPubkey),
		ProgramIDHashchain:   feHex(p.ProgramIDHashchain),
		PayerPubkeyHash:      feHex(p.PayerPubkeyHash),
		DataHash:             feHex(p.DataHash),
		ZoneDataHash:         feHex(p.ZoneDataHash),
		PublicInputHash:      feHex(p.PublicInputHash),
	}

	paramsJson.Inputs = make([]InputParamsJSON, len(p.Inputs))
	for i, in := range p.Inputs {
		paramsJson.Inputs[i] = InputParamsJSON{
			Utxo:                     utxoParamsToJSON(in.Utxo),
			IsDummy:                  feHex(in.IsDummy),
			StatePathElements:        feHexSlice(in.StatePathElements),
			StatePathIndex:           feHex(in.StatePathIndex),
			NullifierLowValue:        feHex(in.NullifierLowValue),
			NullifierNextValue:       feHex(in.NullifierNextValue),
			NullifierLowPathElements: feHexSlice(in.NullifierLowPathElements),
			NullifierLowPathIndex:    feHex(in.NullifierLowPathIndex),
			UtxoTreeRoot:             feHex(in.UtxoTreeRoot),
			NullifierTreeRoot:        feHex(in.NullifierTreeRoot),
			Nullifier:                feHex(in.Nullifier),
			SolanaOwnerPkHash:        feHex(in.SolanaOwnerPkHash),
			NullifierSecret:          feHex(in.NullifierSecret),
		}
	}

	paramsJson.Outputs = make([]OutputParamsJSON, len(p.Outputs))
	for i, out := range p.Outputs {
		paramsJson.Outputs[i] = OutputParamsJSON{
			Utxo:    utxoParamsToJSON(out.Utxo),
			IsDummy: feHex(out.IsDummy),
			Hash:    feHex(out.Hash),
		}
	}

	return paramsJson
}

func (p *TransferParameters) UpdateWithJSON(params TransferParametersJSON) error {
	var err error
	p.NInputs = params.NInputs
	p.NOutputs = params.NOutputs

	if p.ExternalDataHash, err = feFromHex(params.ExternalDataHash); err != nil {
		return err
	}
	if p.P256PubX, err = feFromHex(params.P256PubX); err != nil {
		return err
	}
	if p.P256PubY, err = feFromHex(params.P256PubY); err != nil {
		return err
	}
	if p.P256SigR, err = feFromHex(params.P256SigR); err != nil {
		return err
	}
	if p.P256SigS, err = feFromHex(params.P256SigS); err != nil {
		return err
	}
	if p.PrivateTxHash, err = feFromHex(params.PrivateTxHash); err != nil {
		return err
	}
	if p.P256MessageHash, err = feFromHex(params.P256MessageHash); err != nil {
		return err
	}
	if p.PublicSolAmount, err = feFromHex(params.PublicSolAmount); err != nil {
		return err
	}
	if p.PublicSplAmount, err = feFromHex(params.PublicSplAmount); err != nil {
		return err
	}
	if p.PublicSplAssetPubkey, err = feFromHex(params.PublicSplAssetPubkey); err != nil {
		return err
	}
	if p.ProgramIDHashchain, err = feFromHex(params.ProgramIDHashchain); err != nil {
		return err
	}
	if p.PayerPubkeyHash, err = feFromHex(params.PayerPubkeyHash); err != nil {
		return err
	}
	if p.DataHash, err = feFromHex(params.DataHash); err != nil {
		return err
	}
	if p.ZoneDataHash, err = feFromHex(params.ZoneDataHash); err != nil {
		return err
	}
	if p.PublicInputHash, err = feFromHex(params.PublicInputHash); err != nil {
		return err
	}

	p.Inputs = make([]InputParams, len(params.Inputs))
	for i, in := range params.Inputs {
		utxo, err := utxoParamsFromJSON(in.Utxo)
		if err != nil {
			return err
		}
		input := InputParams{Utxo: utxo}
		if input.IsDummy, err = feFromHex(in.IsDummy); err != nil {
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
		if input.SolanaOwnerPkHash, err = feFromHex(in.SolanaOwnerPkHash); err != nil {
			return err
		}
		if input.NullifierSecret, err = feFromHex(in.NullifierSecret); err != nil {
			return err
		}
		p.Inputs[i] = input
	}

	p.Outputs = make([]OutputParams, len(params.Outputs))
	for i, out := range params.Outputs {
		utxo, err := utxoParamsFromJSON(out.Utxo)
		if err != nil {
			return err
		}
		output := OutputParams{Utxo: utxo}
		if output.IsDummy, err = feFromHex(out.IsDummy); err != nil {
			return err
		}
		if output.Hash, err = feFromHex(out.Hash); err != nil {
			return err
		}
		p.Outputs[i] = output
	}

	return nil
}

func utxoParamsToJSON(u UtxoParams) UtxoParamsJSON {
	return UtxoParamsJSON{
		Domain:        feHex(u.Domain),
		Owner:         feHex(u.Owner),
		Asset:         feHex(u.Asset),
		Amount:        feHex(u.Amount),
		Blinding:      feHex(u.Blinding),
		DataHash:      feHex(u.DataHash),
		ZoneDataHash:  feHex(u.ZoneDataHash),
		ZoneProgramID: feHex(u.ZoneProgramID),
	}
}

func utxoParamsFromJSON(u UtxoParamsJSON) (UtxoParams, error) {
	var out UtxoParams
	var err error
	if out.Domain, err = feFromHex(u.Domain); err != nil {
		return out, err
	}
	if out.Owner, err = feFromHex(u.Owner); err != nil {
		return out, err
	}
	if out.Asset, err = feFromHex(u.Asset); err != nil {
		return out, err
	}
	if out.Amount, err = feFromHex(u.Amount); err != nil {
		return out, err
	}
	if out.Blinding, err = feFromHex(u.Blinding); err != nil {
		return out, err
	}
	if out.DataHash, err = feFromHex(u.DataHash); err != nil {
		return out, err
	}
	if out.ZoneDataHash, err = feFromHex(u.ZoneDataHash); err != nil {
		return out, err
	}
	if out.ZoneProgramID, err = feFromHex(u.ZoneProgramID); err != nil {
		return out, err
	}
	return out, nil
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
