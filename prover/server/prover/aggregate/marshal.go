package aggregate

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// LegJSON is one proof to batch. The public input is the hash the shielded pool
// recomputes, so a caller never sends witness data. A leg of a mixed batch
// names its own inner kind, a leg that names none inherits the request-level
// kind and shape.
type LegJSON struct {
	Proof            common.Proof `json:"proof"`
	PublicInputHash  string       `json:"publicInputHash"`
	InnerCircuitType string       `json:"innerCircuitType,omitempty"`
	NInputs          uint32       `json:"nInputs,omitempty"`
	NOutputs         uint32       `json:"nOutputs,omitempty"`
}

// ParametersJSON is the aggregate proof request. The leg slot list selects the
// proving system.
type ParametersJSON struct {
	CircuitType      string    `json:"circuitType"`
	InnerCircuitType string    `json:"innerCircuitType"`
	NInputs          uint32    `json:"nInputs"`
	NOutputs         uint32    `json:"nOutputs"`
	Legs             []LegJSON `json:"legs"`
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
	if raw.CircuitType != string(common.AggregateCircuitType) {
		return fmt.Errorf("circuit type is %q, want %q", raw.CircuitType, common.AggregateCircuitType)
	}

	slots := make([]common.AggregateSlot, len(raw.Legs))
	for i, leg := range raw.Legs {
		slots[i] = common.AggregateSlot{
			Inner:    common.CircuitType(raw.InnerCircuitType),
			NInputs:  raw.NInputs,
			NOutputs: raw.NOutputs,
		}
		if leg.InnerCircuitType != "" {
			slots[i] = common.AggregateSlot{
				Inner:    common.CircuitType(leg.InnerCircuitType),
				NInputs:  leg.NInputs,
				NOutputs: leg.NOutputs,
			}
		}
	}
	p.Params = Params{Slots: slots}
	if err := p.Params.Validate(); err != nil {
		return err
	}

	p.Legs = make([]Leg, len(raw.Legs))
	for i, leg := range raw.Legs {
		hash, ok := new(big.Int).SetString(trimHexPrefix(leg.PublicInputHash), 16)
		if !ok {
			return fmt.Errorf("leg %d: public input hash %q is not hex", i, leg.PublicInputHash)
		}
		public, err := publicWitness(hash)
		if err != nil {
			return fmt.Errorf("leg %d: %w", i, err)
		}
		p.Legs[i] = Leg{Proof: leg.Proof.Proof, PublicWitness: public}
	}
	return nil
}

func trimHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// singlePublicInput mirrors the witness shape of every SPP transaction circuit,
// one public input and nothing else.
type singlePublicInput struct {
	PublicInputHash frontend.Variable `gnark:",public"`
}

// Define satisfies frontend.Circuit. The witness is filled, never compiled.
func (*singlePublicInput) Define(frontend.API) error { return nil }

func publicWitness(hash *big.Int) (witness.Witness, error) {
	w, err := frontend.NewWitness(
		&singlePublicInput{PublicInputHash: hash},
		ecc.BN254.ScalarField(),
		frontend.PublicOnly(),
	)
	if err != nil {
		return nil, fmt.Errorf("public witness: %w", err)
	}
	return w, nil
}
