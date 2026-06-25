package batchaccountminimal

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// benchCounts is the set of UTXO batch sizes whose Groth16 proving time we
// measure. Largest sizes are setup/memory heavy; select one with
// -bench='BenchmarkProveByCount/utxos_<n>'.
var benchCounts = []int{10, 100, 200, 500, 1000, 2000, 5000, 10000}

func BenchmarkProveByCount(b *testing.B) {
	for _, n := range benchCounts {
		n := n
		b.Run(fmt.Sprintf("utxos_%d", n), func(b *testing.B) {
			benchmarkProveCount(b, n)
		})
	}
}

func benchmarkProveCount(b *testing.B, n int) {
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		NewCircuit(n),
		frontend.WithCompressThreshold(300),
	)
	if err != nil {
		b.Fatal(err)
	}
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}

	assignment := buildAssignment(b, realAmounts(n))
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	for i := 0; i < b.N; i++ {
		if _, err := groth16.Prove(ccs, pk, witness); err != nil {
			b.Fatal(err)
		}
	}
}
