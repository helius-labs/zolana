package merge

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

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
	// the per-input roots, which are published once per tree slot.
	TreeSlot  string `json:"treeSlot"`
	Nullifier string `json:"nullifier"`
}

type OutputParamsJSON struct {
	RingDataHash string `json:"ringDataHash"`
	Hash         string `json:"hash"`
}

type MergeParametersJSON struct {
	CircuitType         common.CircuitType          `json:"circuitType"`
	Inputs              []InputParamsJSON           `json:"inputs"`
	Output              OutputParamsJSON            `json:"output"`
	TreeSlots           []common.TreeSlotParamsJSON `json:"treeSlots"`
	OutputTreeID        string                      `json:"outputTreeId"`
	Mint                string                      `json:"mint"`
	ViewingPk           string                      `json:"viewingPk,omitempty"`
	EphemeralSk         string                      `json:"ephemeralSk,omitempty"`
	OwnerPkHash         string                      `json:"ownerPkHash"`
	UserNullifierPk     string                      `json:"userNullifierPk"`
	UserNullifierSecret string                      `json:"userNullifierSecret"`
	ExternalDataHash    string                      `json:"externalDataHash"`
	PrivateTxHash       string                      `json:"privateTxHash"`
	PublicInputHash     string                      `json:"publicInputHash"`
	AllowDummyInputs    string                      `json:"allowDummyInputs"`
	OutputRingDataHash  string                      `json:"outputRingDataHash"`
	RingProgramID       string                      `json:"ringProgramId"`
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
		Mint:                hex.EncodeToString(p.Mint[:]),
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
	if circuitType == common.MergeCircuitType {
		paramsJson.ViewingPk = hex.EncodeToString(p.ViewingPk[:])
		paramsJson.EphemeralSk = hex.EncodeToString(p.EphemeralSk[:])
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
	if err := p.updateEnvelopeKeys(params); err != nil {
		return err
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
	// Required, not defaulted: the secret seeds the private tx blinding and the
	// policy-ring merged output's blinding, which the circuit derives from it. A
	// zero secret makes both computable by an observer, so an omitted field must
	// fail here rather than silently degrade to a known blinding.
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
	if err := decodeFixedHex("mint", params.Mint, p.Mint[:]); err != nil {
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

func (p *MergeParameters) updateEnvelopeKeys(params MergeParametersJSON) error {
	clear(p.ViewingPk[:])
	clear(p.EphemeralSk[:])
	if p.CircuitType == common.MergeRingCircuitType {
		if params.ViewingPk != "" || params.EphemeralSk != "" {
			return fmt.Errorf("merge-ring: viewingPk and ephemeralSk must be absent on the ring rail")
		}
		return nil
	}
	if p.CircuitType != common.MergeCircuitType {
		return fmt.Errorf("merge: unsupported circuit type %q", p.CircuitType)
	}
	if err := decodeFixedHex("viewingPk", params.ViewingPk, p.ViewingPk[:]); err != nil {
		return err
	}
	if _, err := ecdh.P256().NewPublicKey(p.ViewingPk[:]); err != nil {
		return fmt.Errorf("merge: viewingPk is not an uncompressed P-256 point: %w", err)
	}
	if err := decodeFixedHex("ephemeralSk", params.EphemeralSk, p.EphemeralSk[:]); err != nil {
		return err
	}
	if p.EphemeralSk == ([32]byte{}) {
		return fmt.Errorf("merge: ephemeralSk must be non-zero")
	}
	return nil
}

func decodeFixedHex(name, value string, dst []byte) error {
	if value == "" {
		return fmt.Errorf("merge: %s is required", name)
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		return fmt.Errorf("merge: %s: %w", name, err)
	}
	if len(decoded) != len(dst) {
		return fmt.Errorf("merge: %s must be %d bytes, got %d", name, len(dst), len(decoded))
	}
	copy(dst, decoded)
	return nil
}
