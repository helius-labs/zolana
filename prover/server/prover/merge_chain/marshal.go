package merge_chain

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/prover/common"
)

// LegJSON is one merge proof and the per-slot values its public input folds.
// The folds themselves are derived here, so a caller cannot send a preimage
// that disagrees with the values it sent.
type LegJSON struct {
	Proof              common.Proof `json:"proof"`
	Nullifiers         []string     `json:"nullifiers"`
	UtxoTreeRoots      []string     `json:"utxoTreeRoots"`
	NullifierTreeRoots []string     `json:"nullifierTreeRoots"`
	InputUtxoHashes    []string     `json:"inputUtxoHashes"`
	OutputUtxoHash     string       `json:"outputUtxoHash"`
	ExternalDataHash   string       `json:"externalDataHash"`
	AllowDummyInputs   string       `json:"allowDummyInputs"`
	SigningPkHash      string       `json:"signingPkHash"`
}

// ParametersJSON is the merge chain proof request. The level shape selects the
// proving system, and the legs must arrive bottom level first.
type ParametersJSON struct {
	CircuitType string    `json:"circuitType"`
	Levels      []int     `json:"levels"`
	Legs        []LegJSON `json:"legs"`
}

type Parameters struct {
	Params Params
	Legs   []Leg
}

func (p *Parameters) UnmarshalJSON(data []byte) error {
	var raw ParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.MergeChainCircuitType) {
		return fmt.Errorf("circuit type is %q, want %q", raw.CircuitType, common.MergeChainCircuitType)
	}

	p.Params = Params{Levels: raw.Levels}
	shape, err := p.Params.Shape()
	if err != nil {
		return err
	}
	if len(raw.Legs) != shape.Legs() {
		return fmt.Errorf("%d legs against a chain of %d", len(raw.Legs), shape.Legs())
	}

	p.Legs = make([]Leg, len(raw.Legs))
	for i, raw := range raw.Legs {
		leg, err := raw.parse()
		if err != nil {
			return fmt.Errorf("leg %d: %w", i, err)
		}
		p.Legs[i] = leg
	}
	return nil
}

func (l LegJSON) parse() (Leg, error) {
	leg := Leg{Proof: l.Proof.Proof}
	vectors := []struct {
		name   string
		raw    []string
		target *[Slots]*big.Int
	}{
		{"nullifiers", l.Nullifiers, &leg.Nullifiers},
		{"utxoTreeRoots", l.UtxoTreeRoots, &leg.UtxoTreeRoots},
		{"nullifierTreeRoots", l.NullifierTreeRoots, &leg.NullifierTreeRoots},
		{"inputUtxoHashes", l.InputUtxoHashes, &leg.InputUtxoHashes},
	}
	for _, vector := range vectors {
		if len(vector.raw) != Slots {
			return leg, fmt.Errorf("%s has %d entries, want %d", vector.name, len(vector.raw), Slots)
		}
		for i, value := range vector.raw {
			parsed, err := parseField(vector.name, value)
			if err != nil {
				return leg, err
			}
			vector.target[i] = parsed
		}
	}

	scalars := []struct {
		name   string
		raw    string
		target **big.Int
	}{
		{"outputUtxoHash", l.OutputUtxoHash, &leg.OutputUtxoHash},
		{"externalDataHash", l.ExternalDataHash, &leg.ExternalDataHash},
		{"allowDummyInputs", l.AllowDummyInputs, &leg.AllowDummyInputs},
		{"signingPkHash", l.SigningPkHash, &leg.SigningPkHash},
	}
	for _, scalar := range scalars {
		parsed, err := parseField(scalar.name, scalar.raw)
		if err != nil {
			return leg, err
		}
		*scalar.target = parsed
	}
	return leg, nil
}

func parseField(name, value string) (*big.Int, error) {
	parsed := new(big.Int)
	if value == "" {
		return parsed, nil
	}
	if err := common.FromHex(parsed, value); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}
