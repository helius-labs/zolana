package shared_test

import (
	"fmt"
	"testing"
	"time"

	"zolana/prover/prover-test/spp/benchprove"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
)

// BenchmarkProveTransfer times the production prove path per circuit type and
// shape against the pinned proving keys. Backend (cpu or gpu) is chosen at
// build time via -tags "cuda icicle", see prover-test/spp/benchprove. Run with
// scripts/bench_gpu.sh, or directly:
//
//	go test -run '^$' -bench BenchmarkProveTransfer -benchtime 10x ./circuits/spp_transaction/shared
func BenchmarkProveTransfer(b *testing.B) {
	allShapes := protocol.SupportedShapes
	// ring_authority ships keys for the square shapes only.
	authorityShapes := []protocol.Shape{
		{NInputs: 1, NOutputs: 1},
		{NInputs: 2, NOutputs: 2},
		{NInputs: 3, NOutputs: 3},
		{NInputs: 4, NOutputs: 4},
	}

	cases := []struct {
		circuitType common.CircuitType
		shapes      []protocol.Shape
		commitments int
		witness     func(tb testing.TB, shape protocol.Shape) frontend.Circuit
	}{
		{
			circuitType: common.TransferRingCircuitType,
			shapes:      allShapes,
			witness: func(tb testing.TB, shape protocol.Shape) frontend.Circuit {
				assignment := buildCircuitAssignment(tb, shape)
				refreshPublicInputHash(tb, assignment)
				return asCustomRingEddsaOnly(assignment)
			},
		},
		{
			circuitType: common.TransferConfidentialCircuitType,
			shapes:      allShapes,
			witness: func(tb testing.TB, shape protocol.Shape) frontend.Circuit {
				return asDefaultRingEddsaOnly(buildDefaultRingEddsaOnlyAssignment(tb, shape))
			},
		},
		{
			circuitType: common.TransferRingAuthorityCircuitType,
			shapes:      authorityShapes,
			witness: func(tb testing.TB, shape protocol.Shape) frontend.Circuit {
				return asCustomRingAuthority(buildRingAuthorityAssignment(tb, shape))
			},
		},
		{
			circuitType: common.TransferP256RingCircuitType,
			shapes:      allShapes,
			commitments: 1,
			witness: func(tb testing.TB, shape protocol.Shape) frontend.Circuit {
				assignment := buildCircuitAssignment(tb, shape)
				owner := spptest.FixedP256Key(tb, 11)
				rewriteInputAsP256(tb, assignment, 0, owner)
				authorization := authorizeP256(tb, assignment, owner, owner)
				return asCustomRingP256(assignment, authorization)
			},
		},
	}

	for _, tc := range cases {
		for _, shape := range tc.shapes {
			name := fmt.Sprintf("%s/%s/inputs_%d_outputs_%d",
				benchprove.Backend(), tc.circuitType, shape.NInputs, shape.NOutputs)
			b.Run(name, func(b *testing.B) {
				benchmarkTransferProve(b, tc.circuitType, shape, tc.commitments, tc.witness)
			})
		}
	}
}

func benchmarkTransferProve(
	b *testing.B,
	circuitType common.CircuitType,
	shape protocol.Shape,
	wantCommitments int,
	buildWitness func(tb testing.TB, shape protocol.Shape) frontend.Circuit,
) {
	sys := benchprove.TransferSystem(b, circuitType, uint32(shape.NInputs), uint32(shape.NOutputs))
	assignment := buildWitness(b, shape)
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatalf("build witness: %v", err)
	}
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		b.Fatalf("build public witness: %v", err)
	}

	// First prove per system pays domain init and (on GPU) device pinning.
	coldStart := time.Now()
	proof, err := benchprove.Prove(sys.ConstraintSystem, sys.ProvingKey, fullWitness)
	if err != nil {
		b.Fatalf("prove: %v", err)
	}
	systemKey := fmt.Sprintf("%s_%d_%d", circuitType, shape.NInputs, shape.NOutputs)
	cold := benchprove.RecordCold(systemKey, time.Since(coldStart))

	if err := groth16.Verify(proof, sys.VerifyingKey, publicWitness); err != nil {
		b.Fatalf("verify against pinned vk: %v", err)
	}
	bn254Proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		b.Fatalf("unexpected proof type %T", proof)
	}
	if got := len(bn254Proof.Commitments); got != wantCommitments {
		b.Fatalf("commitment count: got %d want %d", got, wantCommitments)
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
