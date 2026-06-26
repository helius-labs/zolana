package batchaccount

import (
	"math/big"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

const (
	testMinAmount = 100
	testMaxAmount = 1_000_000
)

// buildAssignment builds a self-consistent witness for len(amounts) UTXOs. An
// entry of nil marks a dummy UTXO: it folds into the hash chain but is exempt
// from the owner/asset/band checks and excluded from the aggregate. Real
// amounts are summed into AggregateAmount and the leaf hashes into HashChain
// off-circuit with the same primitives the circuit re-derives.
func buildAssignment(tb testing.TB, amounts []*big.Int) *Circuit {
	tb.Helper()

	var pubkey [32]byte
	for i := range pubkey {
		pubkey[i] = byte(i + 1)
	}
	owner, err := protocol.SolanaPkField(pubkey)
	if err != nil {
		tb.Fatal(err)
	}
	asset := protocol.SolAsset()

	n := len(amounts)
	circuit := NewCircuit(n)
	circuit.Owner = owner
	circuit.Asset = new(big.Int).Set(asset)
	circuit.MinAmount = big.NewInt(testMinAmount)
	circuit.MaxAmount = big.NewInt(testMaxAmount)

	leaves := make([]*big.Int, n)
	aggregate := new(big.Int)
	for i, amount := range amounts {
		var utxo protocol.Utxo
		if amount == nil {
			utxo = protocol.Utxo{
				Domain:        big.NewInt(0),
				Owner:         big.NewInt(0),
				Asset:         big.NewInt(0),
				Amount:        big.NewInt(0),
				Blinding:      big.NewInt(int64(7000 + i)),
				DataHash:      big.NewInt(0),
				ZoneDataHash:  big.NewInt(0),
				ZoneProgramID: big.NewInt(0),
			}
			circuit.IsDummy[i] = 1
		} else {
			utxo = protocol.Utxo{
				Domain:        big.NewInt(protocol.UtxoDomain),
				Owner:         new(big.Int).Set(owner),
				Asset:         new(big.Int).Set(asset),
				Amount:        new(big.Int).Set(amount),
				Blinding:      big.NewInt(int64(1000 + i)),
				DataHash:      big.NewInt(0),
				ZoneDataHash:  big.NewInt(0),
				ZoneProgramID: big.NewInt(0),
			}
			circuit.IsDummy[i] = 0
			aggregate.Add(aggregate, amount)
		}

		leaf, err := protocol.UtxoHash(utxo)
		if err != nil {
			tb.Fatal(err)
		}
		leaves[i] = leaf
		circuit.Utxos[i] = toCircuitFields(utxo)
	}

	chain, err := protocol.HashChain(leaves)
	if err != nil {
		tb.Fatal(err)
	}
	circuit.HashChain = chain
	circuit.AggregateAmount = aggregate
	return circuit
}

func toCircuitFields(u protocol.Utxo) txcircuit.UtxoCircuitFields {
	return txcircuit.UtxoCircuitFields{
		Domain:        u.Domain,
		Owner:         u.Owner,
		Asset:         u.Asset,
		Amount:        u.Amount,
		Blinding:      u.Blinding,
		DataHash:      u.DataHash,
		ZoneDataHash:  u.ZoneDataHash,
		ZoneProgramID: u.ZoneProgramID,
	}
}

// realAmounts returns n in-band amounts (one per real UTXO).
func realAmounts(n int) []*big.Int {
	amounts := make([]*big.Int, n)
	for i := range amounts {
		amounts[i] = big.NewInt(int64(testMinAmount + i))
	}
	return amounts
}

func TestBatchAccountProves(t *testing.T) {
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

func TestBatchAccountRejectsOutOfBandAmount(t *testing.T) {
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
