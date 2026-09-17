package merge_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	merge "zolana/prover/circuits/spp_merge"
)

func BenchmarkWarmMerge(b *testing.B) {
	assignment := buildValidWitness(b)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, merge.NewMergeCircuit(len(assignment.Inputs)), frontend.WithCompressThreshold(300))
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		b.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		b.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		b.Fatal(err)
	}
	for _, workers := range []int{1, 2, 4} {
		b.Run(fmt.Sprintf("workers_%d", workers), func(b *testing.B) {
			permits := make(chan struct{}, workers)
			b.SetParallelism(workers)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					permits <- struct{}{}
					_, err := groth16.Prove(cs, pk, witness)
					<-permits
					if err != nil {
						b.Error(err)
					}
				}
			})
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "proofs/s")
		})
	}
}
