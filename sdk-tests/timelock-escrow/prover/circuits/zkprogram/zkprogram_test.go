package zkprogram_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/iden3/go-iden3-crypto/poseidon"

	"circuits/zkprogram"
	"zolana/gnarksdk"
	"zolana/prover/prover-test/spp/protocol"
)

type counter struct {
	Value frontend.Variable
}

func (c counter) DataHash(api frontend.API) frontend.Variable {
	return gnarksdk.Poseidon(api, c.Value)
}

type transactionCircuit struct {
	Tx            zkprogram.Transaction
	Input         gnarksdk.Utxo
	State         counter
	Asset         frontend.Variable
	Amount        frontend.Variable
	Owner         frontend.Variable
	PayOwner      frontend.Variable
	PayAmount     frontend.Variable
	PrivateTxHash frontend.Variable `gnark:",public"`
}

func (c *transactionCircuit) Define(api frontend.API) error {
	slots := c.Tx.Slots(2, 2)
	slots.Input(0, zkprogram.PlainHash(api, c.Input))
	slots.Create(api, 1, zkprogram.ProgramOutput(api, c.Owner, c.State, c.Asset, c.Amount))
	slots.Create(api, 0, zkprogram.Payment(c.PayOwner, c.Asset, c.PayAmount))
	api.AssertIsEqual(slots.PrivateTxHash(api), c.PrivateTxHash)
	return nil
}

type programUtxoCircuit struct {
	Account  zkprogram.ProgramUtxo[counter]
	Expected frontend.Variable `gnark:",public"`
}

func (c *programUtxoCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Account.Hash(api).Value(), c.Expected)
	return nil
}

type plainCircuit struct {
	Utxo     gnarksdk.Utxo
	Expected frontend.Variable `gnark:",public"`
}

func (c *plainCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(zkprogram.PlainHash(api, c.Utxo).Value(), c.Expected)
	return nil
}

type uncreatedOutputCircuit struct {
	Tx     zkprogram.Transaction
	Input  gnarksdk.Utxo
	Public frontend.Variable `gnark:",public"`
}

func (c *uncreatedOutputCircuit) Define(api frontend.API) error {
	slots := c.Tx.Slots(1, 2)
	slots.Input(0, zkprogram.PlainHash(api, c.Input))
	slots.Create(api, 0, zkprogram.Payment(1, 1, 1))
	api.AssertIsEqual(slots.PrivateTxHash(api), c.Public)
	return nil
}

type reusedOutputCircuit struct {
	Tx     zkprogram.Transaction
	Input  gnarksdk.Utxo
	Public frontend.Variable `gnark:",public"`
}

func (c *reusedOutputCircuit) Define(api frontend.API) error {
	slots := c.Tx.Slots(1, 1)
	slots.Input(0, zkprogram.PlainHash(api, c.Input))
	slots.Create(api, 0, zkprogram.Payment(1, 1, 1))
	slots.Create(api, 0, zkprogram.Payment(1, 1, 1))
	api.AssertIsEqual(slots.PrivateTxHash(api), c.Public)
	return nil
}

type uncheckedInputCircuit struct {
	Tx     zkprogram.Transaction
	Public frontend.Variable `gnark:",public"`
}

func (c *uncheckedInputCircuit) Define(api frontend.API) error {
	slots := c.Tx.Slots(1, 1)
	slots.Input(0, zkprogram.InputHash{})
	slots.Create(api, 0, zkprogram.Payment(1, 1, 1))
	api.AssertIsEqual(slots.PrivateTxHash(api), c.Public)
	return nil
}

func compile(t *testing.T, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func solved(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit) bool {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(witness) == nil
}

func must(t *testing.T) func(*big.Int, error) *big.Int {
	return func(value *big.Int, err error) *big.Int {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}

func utxo(owner, asset, amount, blinding, dataHash *big.Int) protocol.Utxo {
	return protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         owner,
		Asset:         asset,
		Amount:        amount,
		Blinding:      blinding,
		DataHash:      dataHash,
		RingDataHash:  new(big.Int),
		RingProgramID: new(big.Int),
	}
}

func utxoAssignment(u protocol.Utxo, treeID int64) gnarksdk.Utxo {
	return gnarksdk.Utxo{
		Domain:        u.Domain,
		Owner:         u.Owner,
		Asset:         u.Asset,
		Amount:        u.Amount,
		Blinding:      u.Blinding,
		DataHash:      u.DataHash,
		RingDataHash:  u.RingDataHash,
		RingProgramID: u.RingProgramID,
		TreeID:        treeID,
	}
}

func TestCreateDerivesEveryOutputFieldAndTheTransactionHash(t *testing.T) {
	cs := compile(t, &transactionCircuit{})
	first, seed, treeID := big.NewInt(41), big.NewInt(42), big.NewInt(2)
	outputSeed := must(t)(protocol.OutputBlindingSeed(first, seed))
	payment := utxo(big.NewInt(11), big.NewInt(13), big.NewInt(25), must(t)(protocol.OutputBlinding(first, outputSeed, 0)), new(big.Int))
	account := utxo(big.NewInt(12), big.NewInt(13), big.NewInt(7), must(t)(protocol.OutputBlinding(first, outputSeed, 1)), must(t)(poseidon.Hash([]*big.Int{big.NewInt(9)})))
	source := utxo(big.NewInt(14), big.NewInt(13), big.NewInt(32), big.NewInt(15), new(big.Int))
	expected := must(t)(protocol.PrivateTxHash(
		[]*big.Int{must(t)(protocol.UtxoHash(source, treeID)), new(big.Int)},
		[]*big.Int{must(t)(protocol.UtxoHash(payment, treeID)), must(t)(protocol.UtxoHash(account, treeID))},
		[]*big.Int{new(big.Int), new(big.Int)},
		big.NewInt(34),
		must(t)(protocol.PrivateTxBlinding(first, seed)),
	))
	assignment := func(value, blindingSeed int64) *transactionCircuit {
		return &transactionCircuit{
			Tx: zkprogram.Transaction{
				ExternalDataHash: 34,
				FirstNullifier:   41,
				BlindingSeed:     blindingSeed,
				OutputTreeID:     2,
			},
			Input:         utxoAssignment(source, 2),
			State:         counter{Value: value},
			Asset:         13,
			Amount:        7,
			Owner:         12,
			PayOwner:      11,
			PayAmount:     25,
			PrivateTxHash: expected,
		}
	}

	got := [3]bool{
		solved(t, cs, assignment(9, 42)),
		solved(t, cs, assignment(10, 42)),
		solved(t, cs, assignment(9, 43)),
	}
	if got != [3]bool{true, false, false} {
		t.Fatalf("valid, other state, other blinding seed: got %v", got)
	}
}

func TestProgramUtxoInputBindsItsState(t *testing.T) {
	cs := compile(t, &programUtxoCircuit{})
	dataHash := must(t)(poseidon.Hash([]*big.Int{big.NewInt(7)}))
	u := utxo(big.NewInt(11), big.NewInt(13), big.NewInt(25), big.NewInt(17), dataHash)
	expected := must(t)(protocol.UtxoHash(u, big.NewInt(3)))
	assignment := func(value int64) *programUtxoCircuit {
		return &programUtxoCircuit{
			Account:  zkprogram.ProgramUtxo[counter]{Utxo: utxoAssignment(u, 3), State: counter{Value: value}},
			Expected: expected,
		}
	}

	if got := [2]bool{solved(t, cs, assignment(7)), solved(t, cs, assignment(8))}; got != [2]bool{true, false} {
		t.Fatalf("valid, other state: got %v", got)
	}
}

func TestPlainHashRejectsProgramState(t *testing.T) {
	cs := compile(t, &plainCircuit{})
	assignment := func(u protocol.Utxo) *plainCircuit {
		return &plainCircuit{Utxo: utxoAssignment(u, 2), Expected: must(t)(protocol.UtxoHash(u, big.NewInt(2)))}
	}
	plain := utxo(big.NewInt(11), big.NewInt(13), big.NewInt(25), big.NewInt(17), new(big.Int))
	withState := utxo(big.NewInt(11), big.NewInt(13), big.NewInt(25), big.NewInt(17), big.NewInt(5))

	if got := [2]bool{solved(t, cs, assignment(plain)), solved(t, cs, assignment(withState))}; got != [2]bool{true, false} {
		t.Fatalf("plain, with state: got %v", got)
	}
}

func TestSlotsRejectUncreatedAndReusedOutputs(t *testing.T) {
	for name, circuit := range map[string]frontend.Circuit{
		"uncreated output": &uncreatedOutputCircuit{},
		"reused output":    &reusedOutputCircuit{},
		"unchecked input":  &uncheckedInputCircuit{},
	} {
		if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit); err == nil {
			t.Fatalf("%s: compiled", name)
		}
	}
}
