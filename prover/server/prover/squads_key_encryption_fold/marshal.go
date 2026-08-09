package squads_key_encryption_fold

import (
	"encoding/json"
	"fmt"
	"math/big"

	foldcircuit "zolana/prover/circuits/squads/key_encryption_fold"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// LegJSON is one key-encryption proof to fold. The preimage is the exact chain
// input the leg committed to, in order, so the prover can bind the two.
type LegJSON struct {
	Proof    common.Proof `json:"proof"`
	Preimage []string     `json:"preimage"`
}

// ParametersJSON is the fold proof request. The per-leg recipient count and the
// leg count select the proving system.
type ParametersJSON struct {
	CircuitType string    `json:"circuitType"`
	KeysPerLeg  uint32    `json:"keysPerLeg"`
	Legs        []LegJSON `json:"legs"`
}

// Parameters is the parsed request.
type Parameters struct {
	Params Params
	Legs   []Leg
}

func (p *Parameters) UnmarshalJSON(data []byte) error {
	var raw ParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.SquadsKeyEncryptionFoldCircuitType) {
		return fmt.Errorf("circuit type is %q, want %q", raw.CircuitType, common.SquadsKeyEncryptionFoldCircuitType)
	}

	p.Params = Params{KeysPerLeg: raw.KeysPerLeg, Legs: uint32(len(raw.Legs))}
	if err := p.Params.Validate(); err != nil {
		return err
	}
	want := foldcircuit.PreimageLen(int(raw.KeysPerLeg))

	p.Legs = make([]Leg, len(raw.Legs))
	for i, leg := range raw.Legs {
		if len(leg.Preimage) != want {
			return fmt.Errorf("leg %d preimage is %d fields, want %d", i, len(leg.Preimage), want)
		}
		preimage, err := common.FeFromHexSlice(leg.Preimage)
		if err != nil {
			return fmt.Errorf("leg %d preimage: %w", i, err)
		}
		public, err := PublicWitness(preimage)
		if err != nil {
			return fmt.Errorf("leg %d: %w", i, err)
		}
		p.Legs[i] = Leg{Proof: leg.Proof.Proof, PublicWitness: public, Preimage: preimage}
	}
	return nil
}

// singlePublicInput mirrors the witness shape of the key-encryption circuit,
// one public input and nothing else.
type singlePublicInput struct {
	PublicInputHash frontend.Variable `gnark:",public"`
}

// Define satisfies frontend.Circuit. The witness is filled, never compiled.
func (*singlePublicInput) Define(frontend.API) error { return nil }

// PublicWitness rebuilds a leg's public witness from its preimage. The leg's
// public input is the chain over that preimage, so a caller never sends it
// separately and the two cannot drift.
func PublicWitness(preimage []*big.Int) (witness.Witness, error) {
	hash, err := common.HashChain(preimage)
	if err != nil {
		return nil, err
	}
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
