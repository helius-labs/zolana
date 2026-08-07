package keyencryption

import (
	"encoding/json"
	"fmt"

	"zolana/prover/prover/common"
)

type RecipientKeyParamsJSON struct {
	Pubkey []string `json:"pubkey"`
}

type KeyEncryptionParametersJSON struct {
	CircuitType        common.CircuitType       `json:"circuitType"`
	NumKeys            uint32                   `json:"numKeys"`
	OldStateHash       string                   `json:"oldStateHash"`
	ViewingSecretKey   string                   `json:"viewingSecretKey"`
	EphemeralSecretKey string                   `json:"ephemeralSecretKey"`
	NullifierSecret    string                   `json:"nullifierSecret"`
	RecipientKeys      []RecipientKeyParamsJSON `json:"recipientKeys"`
	PublicInputHash    string                   `json:"publicInputHash"`
}

func (p *KeyEncryptionParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.toJSON())
}

func (p *KeyEncryptionParameters) UnmarshalJSON(data []byte) error {
	var params KeyEncryptionParametersJSON
	if err := json.Unmarshal(data, &params); err != nil {
		return err
	}
	return p.updateWithJSON(params)
}

func (p *KeyEncryptionParameters) toJSON() KeyEncryptionParametersJSON {
	out := KeyEncryptionParametersJSON{
		CircuitType:        common.SquadsKeyEncryptionCircuitType,
		NumKeys:            p.NumKeys,
		OldStateHash:       common.FeHex(p.OldStateHash),
		ViewingSecretKey:   common.FeHex(p.ViewingSecretKey),
		EphemeralSecretKey: common.FeHex(p.EphemeralSecretKey),
		NullifierSecret:    common.FeHex(p.NullifierSecret),
		PublicInputHash:    common.FeHex(p.PublicInputHash),
	}
	out.RecipientKeys = make([]RecipientKeyParamsJSON, len(p.RecipientKeys))
	for i, k := range p.RecipientKeys {
		out.RecipientKeys[i] = RecipientKeyParamsJSON{Pubkey: common.FeHexSlice(k.Pubkey[:])}
	}
	return out
}

func (p *KeyEncryptionParameters) updateWithJSON(params KeyEncryptionParametersJSON) error {
	var err error
	p.NumKeys = params.NumKeys

	if p.OldStateHash, err = common.FeFromHex(params.OldStateHash); err != nil {
		return err
	}
	if p.ViewingSecretKey, err = common.FeFromHex(params.ViewingSecretKey); err != nil {
		return err
	}
	if p.EphemeralSecretKey, err = common.FeFromHex(params.EphemeralSecretKey); err != nil {
		return err
	}
	if p.NullifierSecret, err = common.FeFromHex(params.NullifierSecret); err != nil {
		return err
	}
	if p.PublicInputHash, err = common.FeFromHex(params.PublicInputHash); err != nil {
		return err
	}

	p.RecipientKeys = make([]RecipientKeyParams, len(params.RecipientKeys))
	for i, k := range params.RecipientKeys {
		pk, err := common.FeFromHexSlice(k.Pubkey)
		if err != nil {
			return err
		}
		if len(pk) != 65 {
			return fmt.Errorf("recipient key %d pubkey must be 65 bytes, got %d", i, len(pk))
		}
		for j := 0; j < 65; j++ {
			p.RecipientKeys[i].Pubkey[j] = pk[j]
		}
	}
	return nil
}
