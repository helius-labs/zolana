package merge_test

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"zolana/prover/prover-test/spp/benchprove"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
)

// BenchmarkProveMerge times the fixed 8-in/1-out merge circuits against the
// pinned proving keys, backend chosen at build time via the cuda tag. See
// BenchmarkProveTransfer for the run recipe.
func BenchmarkProveMerge(b *testing.B) {
	cases := []struct {
		circuitType common.CircuitType
		witness     func(tb testing.TB) frontend.Circuit
	}{
		{
			circuitType: common.MergeCircuitType,
			witness: func(tb testing.TB) frontend.Circuit {
				return buildDefaultWitness(tb, mergeFixtureOptions{})
			},
		},
		{
			circuitType: common.MergeRingCircuitType,
			witness: func(tb testing.TB) frontend.Circuit {
				return buildRingWitness(tb, big.NewInt(0x5A0E))
			},
		},
	}

	for _, tc := range cases {
		b.Run(fmt.Sprintf("%s/%s/inputs_8_outputs_1", benchprove.Backend(), tc.circuitType), func(b *testing.B) {
			benchmarkMergeProve(b, tc.circuitType, tc.witness)
		})
	}
}

func benchmarkMergeProve(b *testing.B, circuitType common.CircuitType, buildWitness func(tb testing.TB) frontend.Circuit) {
	sys := benchprove.TransferSystem(b, circuitType, 8, 1)
	assignment := buildWitness(b)
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatalf("build witness: %v", err)
	}
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		b.Fatalf("build public witness: %v", err)
	}

	coldStart := time.Now()
	proof, err := benchprove.Prove(sys.ConstraintSystem, sys.ProvingKey, fullWitness)
	if err != nil {
		b.Fatalf("prove: %v", err)
	}
	cold := benchprove.RecordCold(fmt.Sprintf("%s_8_1", circuitType), time.Since(coldStart))

	if err := groth16.Verify(proof, sys.VerifyingKey, publicWitness); err != nil {
		b.Fatalf("verify against pinned vk: %v", err)
	}
	bn254Proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		b.Fatalf("unexpected proof type %T", proof)
	}
	if got := len(bn254Proof.Commitments); got != 0 {
		b.Fatalf("merge proof must carry no commitment, got %d", got)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := benchprove.Prove(sys.ConstraintSystem, sys.ProvingKey, fullWitness); err != nil {
			b.Fatalf("prove: %v", err)
		}
	}
	// ResetTimer deletes user-reported metrics, report only after the loop
	b.ReportMetric(float64(sys.ConstraintSystem.GetNbConstraints()), "constraints")
	b.ReportMetric(cold, "cold_ms")
}
