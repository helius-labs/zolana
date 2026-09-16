package common

import (
	"encoding/json"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/multicommit"
)

type committedCircuit struct {
	Square frontend.Variable `gnark:",public"`
	Value  frontend.Variable
}

func (c *committedCircuit) Define(api frontend.API) error {
	multicommit.WithCommitment(api, func(api frontend.API, challenge frontend.Variable) error {
		api.AssertIsEqual(api.Mul(challenge, c.Square), api.Mul(challenge, c.Value, c.Value))
		return nil
	}, c.Value)
	return nil
}

func TestCommittedProofSerializationVerifies(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &committedCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(&committedCircuit{Square: 9, Value: 3}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(&Proof{Proof: proof})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Proof
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(decoded.Proof, vk, public); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"proofCommitment", "proofCommitmentPok"} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, field)
		broken, _ := json.Marshal(fields)
		if err := json.Unmarshal(broken, &decoded); err == nil {
			t.Fatalf("accepted missing %s", field)
		}
	}
}
