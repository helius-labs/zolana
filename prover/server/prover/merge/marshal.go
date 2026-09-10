package merge

import (
	"encoding/json"
	"fmt"

	"zolana/prover/prover/common"
)

type InputParamsJSON struct {
	Domain                   string   `json:"domain"`
	Amount                   string   `json:"amount"`
	Blinding                 string   `json:"blinding"`
	RingDataHash             string   `json:"ringDataHash"`
	StatePathElements        []string `json:"statePathElements"`
	StatePathIndex           string   `json:"statePathIndex"`
	NullifierLowValue        string   `json:"nullifierLowValue"`
	NullifierNextValue       string   `json:"nullifierNextValue"`
	NullifierLowPathElements []string `json:"nullifierLowPathElements"`
	NullifierLowPathIndex    string   `json:"nullifierLowPathIndex"`
	// TreeSlot indexes the request's treeSlots and stays private; it replaces
	// the per-input roots, which are now published once per tree slot.
	TreeSlot  string `json:"treeSlot"`
	Nullifier string `json:"nullifier"`
}

type OutputParamsJSON struct {
	RingDataHash string `json:"ringDataHash"`
	Hash         string `json:"hash"`
}

type MergeParametersJSON struct {
	CircuitType common.CircuitType `json:"circuitType"`
	Inputs      []InputParamsJSON  `json:"inputs"`
	Output      OutputParamsJSON   `json:"output"`
	// TreeSlots are the InputTrees public tree slots; each input selects one by
	// index.
	TreeSlots []common.TreeSlotParamsJSON `json:"treeSlots"`
	// OutputTreeID is the raw u16 id of the tree the merged output is inserted
	// into.
	OutputTreeID        string `json:"outputTreeId"`
	Asset               string `json:"asset"`
	OwnerPkHash         string `json:"ownerPkHash"`
	UserNullifierPk     string `json:"userNullifierPk"`
	UserNullifierSecret string `json:"userNullifierSecret"`
	ExternalDataHash    string `json:"externalDataHash"`
	PrivateTxHash       string `json:"privateTxHash"`
	PublicInputHash     string `json:"publicInputHash"`
	AllowDummyInputs    string `json:"allowDummyInputs"`
	// OutputRingDataHash is the ring-data hash the calling ring program carries
	// in the merge_ring instruction/event, asserted against Output.RingDataHash.
	// Emitted/consumed only on the merge-ring rail; zero on the default rail.
	OutputRingDataHash string `json:"outputRingDataHash"`
	// RingProgramID is the policy-ring merge circuit's top-level public input
	// (the ring program's pk_field). Emitted/consumed only on the merge-ring rail;
	// the default merge rail leaves it zero.
	RingProgramID string `json:"ringProgramId"`
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
		TreeSlots:           common.TreeSlotsToJSON(p.TreeSlots),
		OutputTreeID:        common.FeHex(p.OutputTreeID),
		Asset:               common.FeHex(p.Asset),
		RingProgramID:       common.FeHex(p.RingProgramID),
		OutputRingDataHash:  common.FeHex(p.OutputRingDataHash),
		OwnerPkHash:         common.FeHex(p.OwnerPkHash),
		UserNullifierPk:     common.FeHex(p.UserNullifierPk),
		UserNullifierSecret: common.FeHex(p.UserNullifierSecret),
		ExternalDataHash:    common.FeHex(p.ExternalDataHash),
		PrivateTxHash:       common.FeHex(p.PrivateTxHash),
		PublicInputHash:     common.FeHex(p.PublicInputHash),
		AllowDummyInputs:    common.FeHex(p.AllowDummyInputs),
	}

	paramsJson.Inputs = make([]InputParamsJSON, len(p.Inputs))
	for i, in := range p.Inputs {
		paramsJson.Inputs[i] = InputParamsJSON{
			Domain:                   common.FeHex(in.Domain),
			Amount:                   common.FeHex(in.Amount),
			Blinding:                 common.FeHex(in.Blinding),
			RingDataHash:             common.FeHex(in.RingDataHash),
			StatePathElements:        common.FeHexSlice(in.StatePathElements),
			StatePathIndex:           common.FeHex(in.StatePathIndex),
			NullifierLowValue:        common.FeHex(in.NullifierLowValue),
			NullifierNextValue:       common.FeHex(in.NullifierNextValue),
			NullifierLowPathElements: common.FeHexSlice(in.NullifierLowPathElements),
			NullifierLowPathIndex:    common.FeHex(in.NullifierLowPathIndex),
			TreeSlot:                 common.FeHex(in.TreeSlot),
			Nullifier:                common.FeHex(in.Nullifier),
		}
	}

	paramsJson.Output = OutputParamsJSON{
		RingDataHash: common.FeHex(p.Output.RingDataHash),
		Hash:         common.FeHex(p.Output.Hash),
	}

	return paramsJson
}

func (p *MergeParameters) UpdateWithJSON(params MergeParametersJSON) error {
	var err error
	p.CircuitType = params.CircuitType
	if p.CircuitType == "" {
		p.CircuitType = common.MergeCircuitType
	}
	if p.TreeSlots, err = common.TreeSlotsFromJSON(params.TreeSlots); err != nil {
		return err
	}
	if p.OutputTreeID, err = common.FeFromHex(params.OutputTreeID); err != nil {
		return err
	}
	if p.RingProgramID, err = common.FeFromHex(params.RingProgramID); err != nil {
		return err
	}
	if p.OutputRingDataHash, err = common.FeFromHex(params.OutputRingDataHash); err != nil {
		return err
	}
	if p.OwnerPkHash, err = common.FeFromHex(params.OwnerPkHash); err != nil {
		return err
	}
	if p.UserNullifierPk, err = common.FeFromHex(params.UserNullifierPk); err != nil {
		return err
	}
	// Required, not defaulted: the secret seeds both the private tx blinding and
	// the merged output's blinding, which the circuit derives from it. A zero
	// secret makes both computable by an observer, so an omitted field must fail
	// here rather than silently degrade to a known blinding.
	if params.UserNullifierSecret == "" {
		return fmt.Errorf("merge: userNullifierSecret is required")
	}
	if p.UserNullifierSecret, err = common.FeFromHex(params.UserNullifierSecret); err != nil {
		return err
	}
	if p.UserNullifierSecret.Sign() == 0 {
		return fmt.Errorf("merge: userNullifierSecret must be non-zero")
	}
	if p.ExternalDataHash, err = common.FeFromHex(params.ExternalDataHash); err != nil {
		return err
	}
	if p.PrivateTxHash, err = common.FeFromHex(params.PrivateTxHash); err != nil {
		return err
	}
	if p.PublicInputHash, err = common.FeFromHex(params.PublicInputHash); err != nil {
		return err
	}
	if p.AllowDummyInputs, err = common.FeFromHex(params.AllowDummyInputs); err != nil {
		return err
	}
	if p.Asset, err = common.FeFromHex(params.Asset); err != nil {
		return err
	}

	p.Inputs = make([]InputParams, len(params.Inputs))
	for i, in := range params.Inputs {
		input := InputParams{}
		if input.Domain, err = common.FeFromHex(in.Domain); err != nil {
			return err
		}
		if input.Amount, err = common.FeFromHex(in.Amount); err != nil {
			return err
		}
		if input.Blinding, err = common.FeFromHex(in.Blinding); err != nil {
			return err
		}
		if input.RingDataHash, err = common.FeFromHex(in.RingDataHash); err != nil {
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
		p.Inputs[i] = input
	}

	output := OutputParams{}
	if output.RingDataHash, err = common.FeFromHex(params.Output.RingDataHash); err != nil {
		return err
	}
	if output.Hash, err = common.FeFromHex(params.Output.Hash); err != nil {
		return err
	}
	p.Output = output

	return nil
}
