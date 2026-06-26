package batchaccountsimple

import (
	"math/big"
	"testing"

	"zolana/prover/prover-test/poseidon"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

const (
	testMinAmount = 100
	testMaxAmount = 1_000_000
)

// simpleLeaf computes the off-circuit leaf hash with the same primitive and
// field order the circuit re-derives.
func simpleLeaf(tb testing.TB, u SimpleUtxoValues) *big.Int {
	tb.Helper()
	leaf, err := poseidon.Hash([]*big.Int{u.Blinding, u.Amount, u.DataHash, u.ZoneDataHash})
	if err != nil {
		tb.Fatal(err)
	}
	return leaf
}

// SimpleUtxoValues holds the off-circuit witness values for one UTXO.
type SimpleUtxoValues struct {
	Blinding     *big.Int
	Amount       *big.Int
	DataHash     *big.Int
	ZoneDataHash *big.Int
}

// buildAssignment builds a self-consistent witness for len(amounts) UTXOs. An
// entry of nil marks a dummy UTXO: it folds into the hash chain but is exempt
// from the band check and excluded from the aggregate.
func buildAssignment(tb testing.TB, amounts []*big.Int) *Circuit {
	tb.Helper()

	n := len(amounts)
	circuit := NewCircuit(n)
	circuit.MinAmount = big.NewInt(testMinAmount)
	circuit.MaxAmount = big.NewInt(testMaxAmount)

	leaves := make([]*big.Int, n)
	aggregate := new(big.Int)
	for i, amount := range amounts {
		var values SimpleUtxoValues
		if amount == nil {
			values = SimpleUtxoValues{
				Blinding:     big.NewInt(int64(7000 + i)),
				Amount:       big.NewInt(0),
				DataHash:     big.NewInt(0),
				ZoneDataHash: big.NewInt(0),
			}
			circuit.IsDummy[i] = 1
		} else {
			values = SimpleUtxoValues{
				Blinding:     big.NewInt(int64(1000 + i)),
				Amount:       new(big.Int).Set(amount),
				DataHash:     big.NewInt(0),
				ZoneDataHash: big.NewInt(0),
			}
			circuit.IsDummy[i] = 0
			aggregate.Add(aggregate, amount)
		}

		leaves[i] = simpleLeaf(tb, values)
		circuit.Utxos[i] = SimpleUtxo{
			Blinding:     values.Blinding,
			Amount:       values.Amount,
			DataHash:     values.DataHash,
			ZoneDataHash: values.ZoneDataHash,
		}
	}

	chain, err := protocol.HashChain(leaves)
	if err != nil {
		tb.Fatal(err)
	}
	circuit.HashChain = chain
	circuit.AggregateAmount = aggregate
	return circuit
}

// realAmounts returns n in-band amounts (one per real UTXO).
func realAmounts(n int) []*big.Int {
	amounts := make([]*big.Int, n)
	for i := range amounts {
		amounts[i] = big.NewInt(int64(testMinAmount + i))
	}
	return amounts
}

func TestBatchAccountSimpleProves(t *testing.T) {
	cases := []struct {
		name    string
		amounts []*big.Int
	}{
		{
			name:    "all_real",
			amounts: realAmounts(10),
		},
		{
			name: "with_dummies",
			amounts: func() []*big.Int {
				a := realAmounts(10)
				a[7], a[8], a[9] = nil, nil, nil
				return a
			}(),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert := test.NewAssert(t)
			circuit := NewCircuit(len(tc.amounts))
			assignment := buildAssignment(t, tc.amounts)
			assert.ProverSucceeded(
				circuit,
				assignment,
				test.WithBackends(backend.GROTH16),
				test.WithCurves(ecc.BN254),
			)
		})
	}
}

func TestBatchAccountSimpleRejectsOutOfBandAmount(t *testing.T) {
	assert := test.NewAssert(t)
	amounts := realAmounts(10)
	amounts[3] = big.NewInt(testMaxAmount + 1)
	circuit := NewCircuit(len(amounts))
	assignment := buildAssignment(t, amounts)
	assert.SolvingFailed(
		circuit,
		assignment,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
	)
}
