package nullifier_fold

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// AppendJSON is one proved append. The span fields are the append circuit's
// public-input preimage. The server recomputes the public input from them, so a
// caller never sends witness data and cannot mislabel a span undetected.
type AppendJSON struct {
	Proof         common.Proof `json:"proof"`
	OldRoot       string       `json:"oldRoot"`
	NewRoot       string       `json:"newRoot"`
	HashchainHash string       `json:"hashchainHash"`
	StartIndex    string       `json:"startIndex"`
}

// ParametersJSON is the fold proof request. The tree height, inner batch size,
// and append count select the proving system.
type ParametersJSON struct {
	CircuitType string       `json:"circuitType"`
	TreeHeight  uint32       `json:"treeHeight"`
	BatchSize   uint32       `json:"batchSize"`
	Appends     []AppendJSON `json:"appends"`
}

type Parameters struct {
	Params Params
	Run    []Append
}

func (p *Parameters) UnmarshalJSON(data []byte) error {
	var raw ParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.NullifierFoldCircuitType) {
		return fmt.Errorf("circuit type is %q, want %q", raw.CircuitType, common.NullifierFoldCircuitType)
	}

	p.Params = Params{
		TreeHeight: raw.TreeHeight,
		BatchSize:  raw.BatchSize,
		Run:        uint32(len(raw.Appends)),
	}
	if err := p.Params.Validate(); err != nil {
		return err
	}

	p.Run = make([]Append, len(raw.Appends))
	for i, item := range raw.Appends {
		span, err := parseSpan(item)
		if err != nil {
			return fmt.Errorf("append %d: %w", i, err)
		}
		public, err := HashChain(span)
		if err != nil {
			return fmt.Errorf("append %d: %w", i, err)
		}
		w, err := publicWitness(public)
		if err != nil {
			return fmt.Errorf("append %d: %w", i, err)
		}
		p.Run[i] = Append{
			Proof:         item.Proof.Proof,
			PublicWitness: w,
			OldRoot:       span[0],
			NewRoot:       span[1],
			HashchainHash: span[2],
			StartIndex:    span[3],
		}
	}
	return nil
}

func parseSpan(item AppendJSON) ([]*big.Int, error) {
	fields := []struct {
		name  string
		value string
	}{
		{"oldRoot", item.OldRoot},
		{"newRoot", item.NewRoot},
		{"hashchainHash", item.HashchainHash},
		{"startIndex", item.StartIndex},
	}
	span := make([]*big.Int, len(fields))
	for i, field := range fields {
		value, ok := new(big.Int).SetString(trimHexPrefix(field.value), 16)
		if !ok {
			return nil, fmt.Errorf("%s %q is not hex", field.name, field.value)
		}
		span[i] = value
	}
	return span, nil
}

func trimHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// singlePublicInput mirrors the append circuit's witness shape, one public
// input and nothing else.
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
