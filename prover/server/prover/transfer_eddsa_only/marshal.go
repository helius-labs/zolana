package transfereddsaonly

import (
	"encoding/json"
	"fmt"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

type UtxoParamsJSON struct {
	Domain        string `json:"domain"`
	Owner         string `json:"owner"`
	Asset         string `json:"asset"`
	Amount        string `json:"amount"`
	Blinding      string `json:"blinding"`
	DataHash      string `json:"dataHash"`
	RingDataHash  string `json:"ringDataHash"`
	RingProgramID string `json:"ringProgramId"`
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
	TreeSlot                 string         `json:"treeSlot"`
	Nullifier                string         `json:"nullifier"`
	OwnerPkHash              string         `json:"ownerPkHash"`
	NullifierSecret          string         `json:"nullifierSecret"`
}

type OutputParamsJSON struct {
	Utxo        UtxoParamsJSON `json:"utxo"`
	IsDummy     string         `json:"isDummy"`
	Hash        string         `json:"hash"`
	OwnerPkHash string         `json:"ownerPkHash"`
	NullifierPk string         `json:"nullifierPk"`
}

type TransferParametersJSON struct {
	CircuitType                  common.CircuitType          `json:"circuitType"`
	NInputs                      uint32                      `json:"nInputs"`
	NOutputs                     uint32                      `json:"nOutputs"`
	Inputs                       []InputParamsJSON           `json:"inputs"`
	Outputs                      []OutputParamsJSON          `json:"outputs"`
	TreeSlots                    []common.TreeSlotParamsJSON `json:"treeSlots"`
	OutputTreeID                 string                      `json:"outputTreeId"`
	ExternalDataHash             string                      `json:"externalDataHash"`
	PrivateTxHash                string                      `json:"privateTxHash"`
	BlindingSeed                 string                      `json:"blindingSeed"`
	PublicAssets                 []string                    `json:"publicAssets"`
	PublicAmounts                []string                    `json:"publicAmounts"`
	RingProgramID                string                      `json:"ringProgramId"`
	SignerPkHashes               []string                    `json:"signerPkHashes"`
	AllowDummyInputs             string                      `json:"allowDummyInputs"`
	PublishedOutputOwnerPkHashes []string                    `json:"publishedOutputOwnerPkHashes"`
	PublicInputHash              string                      `json:"publicInputHash"`
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
	circuitType := p.Variant.CircuitType()
	paramsJson := TransferParametersJSON{
		CircuitType:                  circuitType,
		NInputs:                      p.NInputs,
		NOutputs:                     p.NOutputs,
		TreeSlots:                    common.TreeSlotsToJSON(p.TreeSlots),
		OutputTreeID:                 common.FeHex(p.OutputTreeID),
		ExternalDataHash:             common.FeHex(p.ExternalDataHash),
		PrivateTxHash:                common.FeHex(p.PrivateTxHash),
		BlindingSeed:                 common.FeHex(p.BlindingSeed),
		PublicAssets:                 common.FeHexSlice(p.PublicAssets),
		PublicAmounts:                common.FeHexSlice(p.PublicAmounts),
		RingProgramID:                common.FeHex(p.RingProgramID),
		SignerPkHashes:               common.FeHexSlice(p.SignerPkHashes),
		AllowDummyInputs:             common.FeHex(p.AllowDummyInputs),
		PublishedOutputOwnerPkHashes: common.FeHexSlice(p.PublishedOutputOwnerPkHashes),
		PublicInputHash:              common.FeHex(p.PublicInputHash),
	}

	paramsJson.Inputs = make([]InputParamsJSON, len(p.Inputs))
	for i, in := range p.Inputs {
		paramsJson.Inputs[i] = InputParamsJSON{
			Utxo:                     utxoParamsToJSON(in.Utxo),
			IsDummy:                  common.FeHex(in.IsDummy),
			StatePathElements:        common.FeHexSlice(in.StatePathElements),
			StatePathIndex:           common.FeHex(in.StatePathIndex),
			NullifierLowValue:        common.FeHex(in.NullifierLowValue),
			NullifierNextValue:       common.FeHex(in.NullifierNextValue),
			NullifierLowPathElements: common.FeHexSlice(in.NullifierLowPathElements),
			NullifierLowPathIndex:    common.FeHex(in.NullifierLowPathIndex),
			TreeSlot:                 common.FeHex(in.TreeSlot),
			Nullifier:                common.FeHex(in.Nullifier),
			OwnerPkHash:              common.FeHex(in.OwnerPkHash),
			NullifierSecret:          common.FeHex(in.NullifierSecret),
		}
	}

	paramsJson.Outputs = make([]OutputParamsJSON, len(p.Outputs))
	for i, out := range p.Outputs {
		paramsJson.Outputs[i] = OutputParamsJSON{
			Utxo:        utxoParamsToJSON(out.Utxo),
			IsDummy:     common.FeHex(out.IsDummy),
			Hash:        common.FeHex(out.Hash),
			OwnerPkHash: common.FeHex(out.OwnerPkHash),
			NullifierPk: common.FeHex(out.NullifierPk),
		}
	}

	return paramsJson
}

func (p *TransferParameters) UpdateWithJSON(params TransferParametersJSON) error {
	var err error
	p.NInputs = params.NInputs
	p.NOutputs = params.NOutputs
	p.Variant = variantFromCircuitType(params.CircuitType)
	if p.TreeSlots, err = common.TreeSlotsFromJSON(params.TreeSlots); err != nil {
		return err
	}
	if p.OutputTreeID, err = common.FeFromHex(params.OutputTreeID); err != nil {
		return err
	}

	if p.ExternalDataHash, err = common.FeFromHex(params.ExternalDataHash); err != nil {
		return err
	}
	if p.PrivateTxHash, err = common.FeFromHex(params.PrivateTxHash); err != nil {
		return err
	}
	// Required and non-zero, not defaulted: the circuit derives the private tx
	// blinding and every output blinding from this root seed, so a zero or
	// omitted seed hands an observer a known blinding and predictable output
	// blindings. Fail at parse time rather than as a confusing proving error.
	if params.BlindingSeed == "" {
		return fmt.Errorf("spp: blindingSeed is required")
	}
	if p.BlindingSeed, err = common.FeFromHex(params.BlindingSeed); err != nil {
		return err
	}
	if p.BlindingSeed.Sign() == 0 {
		return fmt.Errorf("spp: blindingSeed must not be zero")
	}
	if len(params.PublicAssets) != txcircuit.NPublicSlots || len(params.PublicAmounts) != txcircuit.NPublicSlots {
		return fmt.Errorf(
			"spp: public slot count mismatch: got %d assets and %d amounts, want %d",
			len(params.PublicAssets), len(params.PublicAmounts), txcircuit.NPublicSlots,
		)
	}
	if p.PublicAssets, err = common.FeFromHexSlice(params.PublicAssets); err != nil {
		return err
	}
	if p.PublicAmounts, err = common.FeFromHexSlice(params.PublicAmounts); err != nil {
		return err
	}
	if p.RingProgramID, err = common.FeFromHex(params.RingProgramID); err != nil {
		return err
	}
	if p.SignerPkHashes, err = common.FeFromHexSlice(params.SignerPkHashes); err != nil {
		return err
	}
	if p.AllowDummyInputs, err = common.FeFromHex(params.AllowDummyInputs); err != nil {
		return err
	}
	if p.PublishedOutputOwnerPkHashes, err = common.FeFromHexSlice(params.PublishedOutputOwnerPkHashes); err != nil {
		return err
	}
	if p.PublicInputHash, err = common.FeFromHex(params.PublicInputHash); err != nil {
		return err
	}

	p.Inputs = make([]InputParams, len(params.Inputs))
	for i, in := range params.Inputs {
		utxo, err := utxoParamsFromJSON(in.Utxo)
		if err != nil {
			return err
		}
		input := InputParams{Utxo: utxo}
		if input.IsDummy, err = common.FeFromHex(in.IsDummy); err != nil {
			return err
		}
		if input.StatePathElements, err = common.FeFromHexSlice(in.StatePathElements); err != nil {
			return err
		}
		if input.StatePathIndex, err = common.FeFromHex(in.StatePathIndex); err != nil {
			return err
		}
		if input.NullifierLowValue, err = common.FeFromHex(in.NullifierLowValue); err != nil {
			return err
		}
		if input.NullifierNextValue, err = common.FeFromHex(in.NullifierNextValue); err != nil {
			return err
		}
		if input.NullifierLowPathElements, err = common.FeFromHexSlice(in.NullifierLowPathElements); err != nil {
			return err
		}
		if input.NullifierLowPathIndex, err = common.FeFromHex(in.NullifierLowPathIndex); err != nil {
			return err
		}
		if input.TreeSlot, err = common.FeFromHex(in.TreeSlot); err != nil {
			return err
		}
		if input.Nullifier, err = common.FeFromHex(in.Nullifier); err != nil {
			return err
		}
		if input.OwnerPkHash, err = common.FeFromHex(in.OwnerPkHash); err != nil {
			return err
		}
		if input.NullifierSecret, err = common.FeFromHex(in.NullifierSecret); err != nil {
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
		if output.IsDummy, err = common.FeFromHex(out.IsDummy); err != nil {
			return err
		}
		if output.Hash, err = common.FeFromHex(out.Hash); err != nil {
			return err
		}
		if output.OwnerPkHash, err = common.FeFromHex(out.OwnerPkHash); err != nil {
			return err
		}
		if output.NullifierPk, err = common.FeFromHex(out.NullifierPk); err != nil {
			return err
		}
		p.Outputs[i] = output
	}

	return nil
}

func utxoParamsToJSON(u UtxoParams) UtxoParamsJSON {
	return UtxoParamsJSON{
		Domain:        common.FeHex(u.Domain),
		Owner:         common.FeHex(u.Owner),
		Asset:         common.FeHex(u.Asset),
		Amount:        common.FeHex(u.Amount),
		Blinding:      common.FeHex(u.Blinding),
		DataHash:      common.FeHex(u.DataHash),
		RingDataHash:  common.FeHex(u.RingDataHash),
		RingProgramID: common.FeHex(u.RingProgramID),
	}
}

func utxoParamsFromJSON(u UtxoParamsJSON) (UtxoParams, error) {
	var out UtxoParams
	var err error
	if out.Domain, err = common.FeFromHex(u.Domain); err != nil {
		return out, err
	}
	if out.Owner, err = common.FeFromHex(u.Owner); err != nil {
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
	if out.DataHash, err = common.FeFromHex(u.DataHash); err != nil {
		return out, err
	}
	if out.RingDataHash, err = common.FeFromHex(u.RingDataHash); err != nil {
		return out, err
	}
	if out.RingProgramID, err = common.FeFromHex(u.RingProgramID); err != nil {
		return out, err
	}
	return out, nil
}
