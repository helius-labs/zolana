package shared_test

import (
	"math/big"
	"testing"
	. "zolana/prover/circuits/spp_transaction/shared"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type paddingIndependentHashCircuit struct {
	Inputs, Outputs, Addresses []frontend.Variable
	Blinding                   frontend.Variable
	Expected                   frontend.Variable `gnark:",public"`
}

func (c *paddingIndependentHashCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(PrivateTxHashCircuit(api, c.Inputs, c.Outputs, c.Addresses, c.Blinding), c.Expected)
	return nil
}

func TestPrivateTxHashCircuitIgnoresPaddingAndBindsRealEntries(t *testing.T) {
	expected := spptest.MustPrivateTxHash(t,
		[]*big.Int{big.NewInt(11), big.NewInt(12)},
		[]*big.Int{big.NewInt(21)},
		[]*big.Int{big.NewInt(31)}, big.NewInt(41))
	cases := []struct {
		name                       string
		inputs, outputs, addresses []frontend.Variable
		blinding                   frontend.Variable
		valid                      bool
	}{
		{"compact", []frontend.Variable{11, 12}, []frontend.Variable{21}, []frontend.Variable{31}, 41, true},
		{"padded", []frontend.Variable{0, 11, 0, 12}, []frontend.Variable{0, 21, 0}, []frontend.Variable{0, 31, 0, 0}, 41, true},
		{"reordered inputs", []frontend.Variable{12, 11}, []frontend.Variable{21}, []frontend.Variable{31}, 41, false},
		{"omitted input", []frontend.Variable{11, 0}, []frontend.Variable{21}, []frontend.Variable{31}, 41, false},
		{"changed output", []frontend.Variable{11, 12}, []frontend.Variable{22}, []frontend.Variable{31}, 41, false},
		{"omitted address", []frontend.Variable{11, 12}, []frontend.Variable{21}, []frontend.Variable{0}, 41, false},
		{"changed blinding", []frontend.Variable{11, 12}, []frontend.Variable{21}, []frontend.Variable{31}, 42, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			circuit := &paddingIndependentHashCircuit{
				Inputs: make([]frontend.Variable, len(tc.inputs)), Outputs: make([]frontend.Variable, len(tc.outputs)),
				Addresses: make([]frontend.Variable, len(tc.addresses)),
			}
			assignment := &paddingIndependentHashCircuit{
				Inputs: tc.inputs, Outputs: tc.outputs, Addresses: tc.addresses, Blinding: tc.blinding, Expected: expected,
			}
			err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
			if (err == nil) != tc.valid {
				t.Fatalf("solving error = %v, want valid %v", err, tc.valid)
			}
		})
	}
}

func TestCircuitRejectsExternalDataHashOutsideThePublicInputHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.ExternalDataHash = spptest.Fe(301)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

func TestPrivateTxHashDoesNotBindExternalData(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.ExternalDataHash = spptest.Fe(301)
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestCircuitRejectsWrongBlindingSeed: a different root seed invalidates the output
// blindings and the private tx hash at once.
func TestCircuitRejectsWrongBlindingSeed(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	assignment.BlindingSeed = spptest.Fe(4243)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}

// TestCircuitRejectsForeignPrivateTxBlinding publishes a private_tx_hash over
// a blinding the circuit did not derive, with the rest of the witness
// consistent, so the derivation check alone rejects it. A prover cannot pick
// the blinding, zero included.
func TestCircuitRejectsForeignPrivateTxBlinding(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCustomRingEddsaOnlyCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	inputHashes := make([]*big.Int, len(assignment.Inputs))
	for i := range assignment.Inputs {
		inputHashes[i] = testUtxoHash(t, circuitFieldsToUtxo(assignment.Inputs[i].Utxo), assignment.inputTreeID(i))
	}
	assignment.PrivateTxHash = spptest.MustPrivateTxHash(
		t,
		inputHashes,
		spptest.ToBigInts(assignment.OutputHashes()),
		noAddressNullifiers(len(inputHashes)),
		spptest.Fe(0xB11E),
	)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, asCustomRingEddsaOnly(assignment), test.WithCurves(ecc.BN254))
}
