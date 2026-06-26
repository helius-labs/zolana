package batchaccountminimal

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

// minimalLeaf computes the off-circuit leaf hash with the same primitive and
// field order the circuit re-derives.
func minimalLeaf(tb testing.TB, amount, blinding *big.Int) *big.Int {
	tb.Helper()
	leaf, err := poseidon.Hash([]*big.Int{amount, blinding})
	if err != nil {
		tb.Fatal(err)
	}
	return leaf
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
		var amt, blinding *big.Int
		if amount == nil {
			amt = big.NewInt(0)
			blinding = big.NewInt(int64(7000 + i))
			circuit.IsDummy[i] = 1
		} else {
			amt = new(big.Int).Set(amount)
			blinding = big.NewInt(int64(1000 + i))
			circuit.IsDummy[i] = 0
			aggregate.Add(aggregate, amount)
		}

		leaves[i] = minimalLeaf(tb, amt, blinding)
		circuit.Utxos[i] = MinimalUtxo{Amount: amt, Blinding: blinding}
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

func TestBatchAccountMinimalProves(t *testing.T) {
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

func TestBatchAccountMinimalRejectsOutOfBandAmount(t *testing.T) {
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
