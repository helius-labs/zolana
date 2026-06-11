package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/spp/circuit/gadget"
	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type hashParityCircuit struct {
	Utxo                 UtxoCircuitFields
	NullifierSecret      frontend.Variable
	NullifierPk          frontend.Variable
	OwnerHash            frontend.Variable
	OwnerKeyHash         frontend.Variable
	InputUtxoHashes      []frontend.Variable
	OutputUtxoHashes     []frontend.Variable
	ExternalDataHash     frontend.Variable
	ExpectedUtxoHash     frontend.Variable `gnark:",public"`
	ExpectedNullifier    frontend.Variable `gnark:",public"`
	ExpectedPrivateTx    frontend.Variable `gnark:",public"`
	ExpectedInputChain   frontend.Variable `gnark:",public"`
	ExpectedOutputChain  frontend.Variable `gnark:",public"`
	ExpectedOutputCount  int               `gnark:"-"`
	ExpectedInputCount   int               `gnark:"-"`
	CompileExpectedWidth int               `gnark:"-"`
}

func (c *hashParityCircuit) Define(api frontend.API) error {
	if c.ExpectedInputCount > 0 && c.ExpectedInputCount != len(c.InputUtxoHashes) {
		panic("spp hash parity circuit: unexpected input hash count")
	}
	if c.ExpectedOutputCount > 0 && c.ExpectedOutputCount != len(c.OutputUtxoHashes) {
		panic("spp hash parity circuit: unexpected output hash count")
	}

	utxoHash := UtxoHashCircuit(api, c.Utxo)
	api.AssertIsEqual(utxoHash, c.ExpectedUtxoHash)

	nullifierPk := NullifierPkCircuit(api, c.NullifierSecret)
	api.AssertIsEqual(nullifierPk, c.NullifierPk)

	ownerHash := OwnerHashCircuit(api, c.OwnerKeyHash, c.NullifierPk)
	api.AssertIsEqual(ownerHash, c.OwnerHash)

	nullifier := NullifierHashCircuit(api, utxoHash, c.Utxo.Blinding, c.NullifierSecret)
	api.AssertIsEqual(nullifier, c.ExpectedNullifier)

	inputChain := gadget.HashChain(api, c.InputUtxoHashes)
	outputChain := gadget.HashChain(api, c.OutputUtxoHashes)
	api.AssertIsEqual(inputChain, c.ExpectedInputChain)
	api.AssertIsEqual(outputChain, c.ExpectedOutputChain)

	privateTx := PrivateTxHashCircuit(
		api,
		c.InputUtxoHashes,
		c.OutputUtxoHashes,
		c.ExternalDataHash,
	)
	api.AssertIsEqual(privateTx, c.ExpectedPrivateTx)
	return nil
}

func TestHashCircuitMatchesNative(t *testing.T) {
	assert := test.NewAssert(t)

	utxo := protocol.Utxo{
		Domain:        spptest.Fe(1),
		Owner:         spptest.Fe(2),
		AssetID:       spptest.Fe(3),
		AssetAmount:   spptest.Fe(4),
		Blinding:      spptest.Fe(5),
		DataHash:      spptest.Fe(6),
		ZoneDataHash:  spptest.Fe(7),
		ZoneProgramID: spptest.Fe(8),
	}
	utxoHash := spptest.MustUtxoHash(t, utxo)
	nullifierSecret := spptest.Fe(99)
	nullifierPk := spptest.MustNullifierPk(t, nullifierSecret)
	ownerKeyHash := spptest.Fe(45)
	ownerHash := spptest.MustOwnerHash(t, ownerKeyHash, nullifierPk)
	nullifier := spptest.MustNullifierHash(t, utxoHash, utxo.Blinding, nullifierSecret)

	inputs := []*big.Int{utxoHash}
	outputs := []*big.Int{spptest.Fe(21), spptest.Fe(22)}
	externalDataHash := spptest.Fe(31)
	inputChain := spptest.MustHashChain(t, inputs)
	outputChain := spptest.MustHashChain(t, outputs)
	privateTx := spptest.MustPrivateTxHash(t, inputs, outputs, externalDataHash)

	circuit := &hashParityCircuit{
		InputUtxoHashes:     make([]frontend.Variable, len(inputs)),
		OutputUtxoHashes:    make([]frontend.Variable, len(outputs)),
		ExpectedInputCount:  len(inputs),
		ExpectedOutputCount: len(outputs),
	}
	assignment := &hashParityCircuit{
		Utxo: UtxoCircuitFields{
			Domain:        utxo.Domain,
			Owner:         utxo.Owner,
			AssetID:       utxo.AssetID,
			AssetAmount:   utxo.AssetAmount,
			Blinding:      utxo.Blinding,
			DataHash:      utxo.DataHash,
			ZoneDataHash:  utxo.ZoneDataHash,
			ZoneProgramID: utxo.ZoneProgramID,
		},
		NullifierSecret:     nullifierSecret,
		NullifierPk:         nullifierPk,
		OwnerHash:           ownerHash,
		OwnerKeyHash:        ownerKeyHash,
		InputUtxoHashes:     []frontend.Variable{utxoHash},
		OutputUtxoHashes:    []frontend.Variable{outputs[0], outputs[1]},
		ExternalDataHash:    externalDataHash,
		ExpectedUtxoHash:    utxoHash,
		ExpectedNullifier:   nullifier,
		ExpectedPrivateTx:   privateTx,
		ExpectedInputChain:  inputChain,
		ExpectedOutputChain: outputChain,
		ExpectedInputCount:  len(inputs),
		ExpectedOutputCount: len(outputs),
	}

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	assert.ProverSucceeded(
		circuit,
		assignment,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.NoSerializationChecks(),
	)
}

func TestHashCircuitCompileRepresentative(t *testing.T) {
	circuit := &hashParityCircuit{
		InputUtxoHashes:  make([]frontend.Variable, 1),
		OutputUtxoHashes: make([]frontend.Variable, 2),
	}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatalf("compile hash parity circuit: %v", err)
	}
}
