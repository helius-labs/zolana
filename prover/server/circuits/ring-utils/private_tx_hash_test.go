package ringutils

import (
	"math/big"
	"testing"

	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

const (
	fixtureRingProgramID = 0x5A
	fixtureTreeID        = 7
)

type fixtureUtxo struct {
	treeID, ownerHash, asset, amount, blinding, dataHash, ringDataHash, ringProgramID *big.Int
}

func (u fixtureUtxo) variable() Utxo {
	return Utxo{
		TreeID:          u.treeID,
		OwnerHash:       u.ownerHash,
		Asset:           u.asset,
		Amount:          u.amount,
		Blinding:        u.blinding,
		ProgramDataHash: u.dataHash,
		RingDataHash:    u.ringDataHash,
		RingProgramID:   u.ringProgramID,
	}
}

// hash mirrors utxoHashGadget; protocol.UtxoHash still hashes the six-field
// preimage without the tree id.
func (u fixtureUtxo) hash(t *testing.T) *big.Int {
	t.Helper()
	ownerUtxoHash, err := poseidon.Hash([]*big.Int{u.ownerHash, u.blinding})
	if err != nil {
		t.Fatal(err)
	}
	ringHash, err := poseidon.Hash([]*big.Int{u.ringDataHash, u.ringProgramID})
	if err != nil {
		t.Fatal(err)
	}
	h, err := poseidon.Hash([]*big.Int{
		big.NewInt(protocol.UtxoDomain), u.treeID, u.asset, u.amount, u.dataHash, ringHash, ownerUtxoHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func ringUtxo(seed, amount int64) fixtureUtxo {
	return fixtureUtxo{
		treeID:        big.NewInt(fixtureTreeID),
		ownerHash:     big.NewInt(1000 + seed),
		asset:         big.NewInt(2),
		amount:        big.NewInt(amount),
		blinding:      big.NewInt(2000 + seed),
		dataHash:      big.NewInt(0),
		ringDataHash:  big.NewInt(3000 + seed),
		ringProgramID: big.NewInt(fixtureRingProgramID),
	}
}

// buildAssignment returns a satisfying witness: two ring inputs, one ring
// output and one free output, no address slots.
func buildAssignment(t *testing.T) *PrivateTxHashCircuit {
	t.Helper()
	inputs := [NumInputs]fixtureUtxo{ringUtxo(1, 60), ringUtxo(2, 40)}
	outputs := [NumOutputs]fixtureUtxo{ringUtxo(3, 70), ringUtxo(4, 30)}
	outputs[1].ringDataHash = big.NewInt(0)
	outputs[1].ringProgramID = big.NewInt(0)

	inputHashes := make([]*big.Int, NumInputs)
	outputHashes := make([]*big.Int, NumOutputs)
	addressHashes := make([]*big.Int, NumInputs)
	for i := range inputs {
		inputHashes[i] = inputs[i].hash(t)
		addressHashes[i] = big.NewInt(0)
	}
	for i := range outputs {
		outputHashes[i] = outputs[i].hash(t)
	}
	externalDataHash := big.NewInt(0xABCDEF)
	blinding := big.NewInt(0xB11D)
	privateTxHash, err := protocol.PrivateTxHash(inputHashes, outputHashes, addressHashes, externalDataHash, blinding)
	if err != nil {
		t.Fatal(err)
	}

	assignment := &PrivateTxHashCircuit{
		Public: PublicInputs{
			PrivateTxHash: privateTxHash,
			RingProgramID: big.NewInt(fixtureRingProgramID),
		},
		ExternalDataHash:  externalDataHash,
		PrivateTxBlinding: blinding,
	}
	for i := range inputs {
		assignment.Inputs[i] = inputs[i].variable()
		assignment.AddressHashes[i] = addressHashes[i]
	}
	for i := range outputs {
		assignment.Outputs[i] = outputs[i].variable()
	}
	return assignment
}

// Compiling without IgnoreUnconstrainedInputs proves every public input,
// RingProgramID included, is constrained.
func TestPrivateTxHashCircuitCompiles(t *testing.T) {
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PrivateTxHashCircuit{}); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func TestPrivateTxHashCircuitSolves(t *testing.T) {
	test.NewAssert(t).SolvingSucceeded(
		&PrivateTxHashCircuit{},
		buildAssignment(t),
		test.WithCurves(ecc.BN254),
	)
}

// A UTXO of another ring cannot be proven under this ring's program id.
func TestPrivateTxHashCircuitRejectsForeignRingUtxo(t *testing.T) {
	assignment := buildAssignment(t)
	assignment.Public.RingProgramID = big.NewInt(fixtureRingProgramID + 1)
	test.NewAssert(t).SolvingFailed(
		&PrivateTxHashCircuit{},
		assignment,
		test.WithCurves(ecc.BN254),
	)
}

func TestPrivateTxHashCircuitRejectsWrongPrivateTxHash(t *testing.T) {
	assignment := buildAssignment(t)
	assignment.Public.PrivateTxHash = big.NewInt(1)
	test.NewAssert(t).SolvingFailed(
		&PrivateTxHashCircuit{},
		assignment,
		test.WithCurves(ecc.BN254),
	)
}
