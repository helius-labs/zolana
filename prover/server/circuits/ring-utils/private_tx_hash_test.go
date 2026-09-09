package ringutils

import (
	"math/big"
	"testing"

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
	domain, treeID, ownerHash, asset, amount, blinding, dataHash, ringDataHash, ringProgramID *big.Int
}

func (u fixtureUtxo) variable() Utxo {
	return Utxo{
		Domain:          u.domain,
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

func (u fixtureUtxo) isUtxo() bool {
	return u.domain.Int64() == protocol.UtxoDomain
}

// hash commits to the utxo under the tree that holds it, matching
// utxoHashGadget.
func (u fixtureUtxo) hash(t *testing.T) *big.Int {
	t.Helper()
	h, err := protocol.UtxoHash(protocol.Utxo{
		Domain:        u.domain,
		Owner:         u.ownerHash,
		Asset:         u.asset,
		Amount:        u.amount,
		Blinding:      u.blinding,
		DataHash:      u.dataHash,
		RingDataHash:  u.ringDataHash,
		RingProgramID: u.ringProgramID,
	}, u.treeID)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// chainElement mirrors the SPP private_tx_hash chains: a real UTXO enters by
// its hash, every other slot as 0.
func (u fixtureUtxo) chainElement(t *testing.T) *big.Int {
	t.Helper()
	if u.isUtxo() {
		return u.hash(t)
	}
	return big.NewInt(0)
}

func ringUtxo(seed, amount int64) fixtureUtxo {
	return fixtureUtxo{
		domain:        big.NewInt(protocol.UtxoDomain),
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

// dummyUtxo is an SPP padding slot: every field zero except the blinding.
func dummyUtxo(seed int64) fixtureUtxo {
	return fixtureUtxo{
		domain:        big.NewInt(protocol.DummyDomain),
		treeID:        big.NewInt(fixtureTreeID),
		ownerHash:     big.NewInt(0),
		asset:         big.NewInt(0),
		amount:        big.NewInt(0),
		blinding:      big.NewInt(2000 + seed),
		dataHash:      big.NewInt(0),
		ringDataHash:  big.NewInt(0),
		ringProgramID: big.NewInt(0),
	}
}

type fixture struct {
	inputs  [NumInputs]fixtureUtxo
	outputs [NumOutputs]fixtureUtxo
}

// twoByTwo is a full transaction: two ring inputs, one ring output and one free
// output, no address slots.
func twoByTwo() fixture {
	f := fixture{
		inputs:  [NumInputs]fixtureUtxo{ringUtxo(1, 60), ringUtxo(2, 40)},
		outputs: [NumOutputs]fixtureUtxo{ringUtxo(3, 70), ringUtxo(4, 30)},
	}
	f.outputs[1].ringDataHash = big.NewInt(0)
	f.outputs[1].ringProgramID = big.NewInt(0)
	return f
}

// withDummies pads the second input and output slots.
func withDummies() fixture {
	f := twoByTwo()
	f.inputs[1] = dummyUtxo(5)
	f.outputs[1] = dummyUtxo(6)
	return f
}

// buildAssignment returns a satisfying witness for the fixture, with the public
// private_tx_hash computed over the SPP chain elements.
func buildAssignment(t *testing.T, f fixture) *PrivateTxHashCircuit {
	t.Helper()
	inputHashes := make([]*big.Int, NumInputs)
	outputHashes := make([]*big.Int, NumOutputs)
	addressNullifiers := make([]*big.Int, NumInputs)
	for i := range f.inputs {
		inputHashes[i] = f.inputs[i].chainElement(t)
		addressNullifiers[i] = big.NewInt(0)
	}
	for i := range f.outputs {
		outputHashes[i] = f.outputs[i].chainElement(t)
	}
	externalDataHash := big.NewInt(0xABCDEF)
	blinding := big.NewInt(0xB11D)
	privateTxHash, err := protocol.PrivateTxHash(inputHashes, outputHashes, addressNullifiers, externalDataHash, blinding)
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
	for i := range f.inputs {
		assignment.Inputs[i] = f.inputs[i].variable()
		assignment.AddressNullifiers[i] = addressNullifiers[i]
	}
	for i := range f.outputs {
		assignment.Outputs[i] = f.outputs[i].variable()
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
		buildAssignment(t, twoByTwo()),
		test.WithCurves(ecc.BN254),
	)
}

// A padding dummy contributes 0 to its chain, exactly as in the SPP circuit, so
// a transaction with fewer real slots than the shape still proves.
func TestPrivateTxHashCircuitSolvesWithDummySlots(t *testing.T) {
	test.NewAssert(t).SolvingSucceeded(
		&PrivateTxHashCircuit{},
		buildAssignment(t, withDummies()),
		test.WithCurves(ecc.BN254),
	)
}

// The old behaviour, folding a dummy by its real UTXO hash, must not verify:
// SPP publishes the hash over zero chain elements for those slots.
func TestPrivateTxHashCircuitRejectsDummyFoldedByHash(t *testing.T) {
	f := withDummies()
	assignment := buildAssignment(t, f)
	inputHashes := []*big.Int{f.inputs[0].hash(t), f.inputs[1].hash(t)}
	outputHashes := []*big.Int{f.outputs[0].hash(t), f.outputs[1].hash(t)}
	addressNullifiers := []*big.Int{big.NewInt(0), big.NewInt(0)}
	folded, err := protocol.PrivateTxHash(
		inputHashes,
		outputHashes,
		addressNullifiers,
		big.NewInt(0xABCDEF),
		big.NewInt(0xB11D),
	)
	if err != nil {
		t.Fatal(err)
	}
	assignment.Public.PrivateTxHash = folded
	test.NewAssert(t).SolvingFailed(
		&PrivateTxHashCircuit{},
		assignment,
		test.WithCurves(ecc.BN254),
	)
}

// A UTXO of another ring cannot be proven under this ring's program id.
func TestPrivateTxHashCircuitRejectsForeignRingUtxo(t *testing.T) {
	assignment := buildAssignment(t, twoByTwo())
	assignment.Public.RingProgramID = big.NewInt(fixtureRingProgramID + 1)
	test.NewAssert(t).SolvingFailed(
		&PrivateTxHashCircuit{},
		assignment,
		test.WithCurves(ecc.BN254),
	)
}

func TestPrivateTxHashCircuitRejectsWrongPrivateTxHash(t *testing.T) {
	assignment := buildAssignment(t, twoByTwo())
	assignment.Public.PrivateTxHash = big.NewInt(1)
	test.NewAssert(t).SolvingFailed(
		&PrivateTxHashCircuit{},
		assignment,
		test.WithCurves(ecc.BN254),
	)
}
